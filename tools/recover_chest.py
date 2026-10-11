#!/usr/bin/env python3
"""Hash-gated recovery of the Chest (E139).

Chest lands: the batch sweeps chest surface:
48 bodies, 12879 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/CHEST.md for the prose and boundaries.
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
    'bl 0xcb623c': 0x00cb623c,
    'bl 0xcb7aa4': 0x00cb7aa4,
    'bl 0xcb7fd4': 0x00cb7fd4,
    'bl 0xcbd0b0': 0x00cbd0b0,
    'bl 0xcbd188': 0x00cbd188,
    'bl 0xcc0ad4': 0x00cc0ad4,
    'bl 0xcc10e0': 0x00cc10e0,
    'bl 0xcc1154': 0x00cc1154,
    'bl 0xcc14ec': 0x00cc14ec,
    'bl 0xcc18ac': 0x00cc18ac,
    'bl 0xcc1954': 0x00cc1954,
    'bl 0xcc2184': 0x00cc2184,
    'bl 0xcc2804': 0x00cc2804,
    'bl 0xcc2850': 0x00cc2850,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__insert_unique_int_const_': 0x0095baf4,
    'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__tree_std::__1::less_int__const_': 0x006ea460,
    'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__': 0x006e9bf8,
    'bl sym.fillQuadBufferColored_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__Vector__int__int_': 0x00d94c88,
    'bl sym.fillQuadBufferDodoEgg_float__int___GLKMatrix4__float__float__float__float__float__int__signed_char__int__int_': 0x00d94218,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.itemTypeIsBlock_ItemType_': 0x004cc11c,
    'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_': 0x004ea3cc,
    'bl sym.itemTypeIsWorkbench_ItemType_': 0x005b2aa0,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.paintedIndexForImageIndex_int_': 0x00a15e28,
    'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_': 0x00a196dc,
    'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_': 0x00a19748,
    'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_': 0x00a19670,
    'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_': 0x00a19598,
    'bl sym.texCoordsForImageIndex_int_': 0x004d6820,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsHalfDepth_Tile__World__intpair_': 0x00a14450,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
}

SPECS = [
    dict(
        name='ce_00',
        method='Chest -[actionTitle]',
        types='@8@0:4',
        start=13359156,
        end=13359336,
        disasm='disasm_worldtileloader_ce_00.txt',
        base_add=13359172,
        base_literal=13359332,
        boundary='ARM.exidx end 0x00cbd8e8 (listing bound); next ObjC IMP 0x00cbd8e8 Chest -[requiresHumanInteraction]',
        selectors={
                 0xcbd8d8: (15236536, 'stringWithFormat:'),
                 0xcbd8dc: (15236704, 'title'),
        },
        imports={
                 0xcbd8d0: (16397288, '__CFConstantStringClassReference'),
                 0xcbd8d4: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xcbd8e0: (15250976, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(13359156, 'push {r4, r5, r6, sl, fp, lr}'), (13359332, 'eorseq r2, sl, r8, lsr 5')],
        calls=[(13359264, 'blx ip'), (13359300, 'blx ip')],
        branches=[],
        semantics=('[Chest -[actionTitle]] (imp 0x00cbd834, 45w): -[actionTitle] (0xcbd834, 45w): returns [NSString stringWithFormat:@"USE %@", [self title]] via objc_msgSend; the format CFString \'USE %@\' cell sits at 0xcbd8d0 and NSString is fetched through the OBJC_CLASS cell at 0xcbd8e0..\n'),
    ),
    dict(
        name='ce_01',
        method='Chest -[addDodoEggDrawQuadData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=13382704,
        end=13384144,
        disasm='disasm_worldtileloader_ce_01.txt',
        base_add=13382732,
        base_literal=13384140,
        boundary='ARM.exidx end 0x00cc39d0 (listing bound); next ObjC IMP 0x00cc39d0 Chest -[interactionRenderItemType]',
        selectors={
                 0xcc39ac: (15236476, 'count'),
                 0xcc39b0: (15236488, 'objectAtIndex:'),
                 0xcc39b4: (15236596, 'dataB'),
                 0xcc39b8: (15236452, 'itemType'),
                 0xcc39bc: (15236592, 'lastObject'),
        },
        imports={
                 0xcc39a8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcc3994: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcc3998: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcc399c: (17167588, 'OBJC_IVAR_$_Chest.shelfRenderItems', 116),
                 0xcc39a4: (17167592, 'OBJC_IVAR_$_Chest.shelfItemDataBs', 132),
                 0xcc39c0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xcc39c8: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
        },
        classes={},
        instructions=[(13382704, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13384140, 'eorseq ip, sb, r0, lsr 13')],
        calls=[(13383104, 'blx ip'), (13383128, 'blx r2'), (13383236, 'blx r4'), (13383260, 'blx r2'), (13383284, 'blx r2'), (13383440, 'bl method.Vector2.operator_float__'), (13383496, 'bl method.Vector2.operator_float__'), (13383544, 'bl 0xcc10e0'), (13384004, 'bl sym.fillQuadBufferDodoEgg_float__int___GLKMatrix4__float__float__float__float__float__int__signed_char__int__int_')],
        branches=[(13382796, 'beq', 13382836), (13382832, 'bne', 13384072), (13382860, 'bge', 13384068), (13382884, 'bge', 13384048), (13383012, 'beq', 13383300), (13383136, 'bne', 13383156), (13383152, 'b', 13384032), (13383296, 'b', 13383332), (13383308, 'bne', 13383328), (13383324, 'b', 13384032), (13383328, 'b', 13383332), (13383340, 'bne', 13384020), (13383356, 'beq', 13384020), (13384044, 'b', 13382876), (13384048, 'b', 13384052), (13384064, 'b', 13382852), (13384068, 'b', 13384072)],
        semantics=('[Chest -[addDodoEggDrawQuadData:fromIndex:]] (imp 0x00cc3430, 360w): [census-lite] -[addDodoEggDrawQuadData:fromIndex:] (0xcc3430, 360w): only chestType 2/5 (else return 0). Same 2x2 shelf loop + cache/inventory resolution as ce_03 (slot = row*2+col; empty -> cached shelfRenderItems/shelfItemDataBs). Emits only for itemType==0x5b (dodo egg) AND dataB!=0 (0xcc36b0). Quad center = floatPos + (5*col-6, 4-5*row, -1.5) via 0xcc10e0 (0xcc3778); struct for sym.fillQuadBufferDodoEgg_..._int__signed_char__int__int_ carries 0.6 (0x3f19999a at +0x40/+0x48) and 0.075 (0x3d99999a at +0x3c/+0x44) floats, itemType/dataB, macroTileOwner*32 (lsl 5); returns the egg-quad count [sp+0x17c]..\n'),
    ),
    dict(
        name='ce_02',
        method='Chest -[addDrawCubeData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=13362624,
        end=13372116,
        disasm='disasm_worldtileloader_ce_02.txt',
        base_add=13362676,
        base_literal=13362820,
        boundary='ARM.exidx end 0x00cc0ad4 (listing bound); next ObjC IMP 0x00cc19fc Chest -[staticGeometryDrawQuadCountForMacroPos:]',
        selectors={
                 0xcbe6c4: (15236752, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:paintColor:'),
                 0xcc0a84: (15236752, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:paintColor:'),
                 0xcc0aa0: (15236476, 'count'),
                 0xcc0aa4: (15236488, 'objectAtIndex:'),
                 0xcc0aa8: (15236596, 'dataB'),
                 0xcc0aac: (15236452, 'itemType'),
                 0xcc0ab0: (15236592, 'lastObject'),
                 0xcc0ab4: (15236524, 'intValue'),
                 0xcc0abc: (15236468, 'objectForKey:'),
                 0xcc0ac0: (15236600, 'dynamicObjectSaveDict'),
                 0xcc0ad0: (15236756, 'fillBufferForBlockOfType:buffer:fromIndex:macroWorldX:macroWorldY:matrix:level:paintColor:size:world:'),
        },
        imports={
                 0xcc0a9c: (17151904, 'objc_msgSend'),
                 0xcc0ab8: (16397128, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xcbe688: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0xcbe68c: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcbe69c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xcbe6c0: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0xcc0a74: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcc0a78: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xcc0a80: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0xcc0a8c: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcc0a90: (17167588, 'OBJC_IVAR_$_Chest.shelfRenderItems', 116),
                 0xcc0a98: (17167592, 'OBJC_IVAR_$_Chest.shelfItemDataBs', 132),
                 0xcc0ac4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xcc0acc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xcbe6a4: (15250992, 'OBJC_CLASS_$_DrawCube'),
                 0xcc0a7c: (15250992, 'OBJC_CLASS_$_DrawCube'),
        },
        instructions=[(13362624, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13372112, 'invalid')],
        calls=[(13362764, 'bl method.Vector.Vector_float__float__float__float_'), (13362932, 'bl 0xcc0ad4'), (13363148, 'bl sym.paintedIndexForImageIndex_int_'), (13363164, 'bl sym.texCoordsForImageIndex_int_'), (13363388, 'bl 0xcc10e0'), (13364164, 'bl loc.imp.objc_msgSend'), (13364240, 'bl 0xcc10e0'), (13365096, 'bl loc.imp.objc_msgSend'), (13365260, 'bl 0xcc10e0'), (13366164, 'bl loc.imp.objc_msgSend'), (13366280, 'bl 0xcc10e0'), (13366736, 'bl 0xcc1154'), (13367584, 'bl loc.imp.objc_msgSend'), (13367664, 'bl 0xcc10e0'), (13368120, 'bl 0xcc1154'), (13368984, 'bl loc.imp.objc_msgSend'), (13369268, 'blx ip'), (13369292, 'blx r2'), (13369400, 'blx r4'), (13369424, 'blx r2'), (13369448, 'blx r2'), (13369464, 'bl sym.itemTypeIsWorkbench_ItemType_'), (13369572, 'blx r5'), (13369592, 'blx r3'), (13369608, 'blx r2'), (13369712, 'bl sym.itemTypeIsBlock_ItemType_'), (13369776, 'bl method.Vector2.operator_float__'), (13369836, 'bl method.Vector2.operator_float__'), (13369888, 'bl 0xcc10e0'), (13370268, 'bl 0xcc14ec'), (13370924, 'bl loc.imp.objc_msgSend'), (13371168, 'bl 0xcc10e0'), (13371204, 'bl 0xcc18ac'), (13371244, 'bl 0xcc1954'), (13371272, 'bl sym.paintedIndexForImageIndex_int_'), (13371284, 'bl sym.paintedIndexForImageIndex_int_'), (13371304, 'bl sym.texCoordsForImageIndex_int_'), (13371320, 'bl sym.texCoordsForImageIndex_int_'), (13371988, 'bl loc.imp.objc_msgSend')],
        branches=[(13362812, 'beq', 13362976), (13362816, 'b', 13362892), (13363008, 'beq', 13363048), (13363044, 'bne', 13371004), (13363116, 'bne', 13363128), (13363140, 'beq', 13363156), (13363252, 'bne', 13363276), (13365136, 'bne', 13369000), (13366200, 'b', 13366236), (13368636, 'b', 13368644), (13369024, 'bge', 13371000), (13369048, 'bge', 13370968), (13369176, 'beq', 13369624), (13369300, 'bne', 13369320), (13369316, 'b', 13370952), (13369476, 'beq', 13369620), (13369620, 'b', 13369656), (13369632, 'bne', 13369652), (13369648, 'b', 13370952), (13369652, 'b', 13369656), (13369724, 'beq', 13370940), (13370964, 'b', 13369040), (13370968, 'b', 13370972), (13370984, 'b', 13369016), (13371000, 'b', 13371004), (13371036, 'beq', 13372004), (13371072, 'beq', 13372004), (13371264, 'beq', 13371292)],
        semantics=('[Chest -[addDrawCubeData:fromIndex:]] (imp 0x00cbe5c0, 2373w): [census] -[addDrawCubeData:fromIndex:] (0xcbe5c0, 2373w / 28 br / 39 call rows; large frame ~0xa00 + vpush d8-d12). Purpose: emit the chest\'s DrawCube quads (chest body/lid) and its shelf item renders into the shared cube buffer, returning the quad count ([sp,0x9cc]). Phases: (1) head 0xcbe5c0-0xcbe768: Vector(1,1,1,1) color at [sp+0x9b8] (Vector ctor call 0xcbe64c), replaced by the RGBA of InteractionObject.paintColor@88 via 0xcc0ad4(&tmp,paintColor,0) with painted flag byte [sp+0x9b7]=1. (2) shelf chests (chestType 2/5): body face image id 0xc4 (196), but 0x73 (115) for type 5 (0xcbe7b0); paintedIndexForImageIndex when painted; texCoordsForImageIndex -> 4 floats [sp+0x980]; one cube face emitted as DrawCube-fill (0xcbe8bc vector builder 0xcc10e0 for center = pos + (5,-1.5) etc.; DrawCube class ref cell 0xcbe6a4). (3) inventory loop 0xcbff60+: per shelf slot: inventoryItems[slot]; non-empty -> [lastObject itemType]/[dataB (short)]; workbench -> dataB := [[[lastObject dynamicObjectSaveDict] objectForKey:@"level"] intValue] (cfstr \'level\' 0xcc00b8); slot grid position = 5*row / 5-5*row offsets (vstr [buf+0x178]/[buf+0x174]); itemTypeIsBlock -> block path (fillBufferForBlockOfType... + 0xcc14ec at 0xcc039c); else item quad path: center = floatPos + (-5+5*col+2, +2+5-5*row, -1.5) via 0xcc10e0/Vector2 + helpers 0xcc1154 (x2). (4) non-shelf chests (not 2/5) 0xcc067c: center = pos + (5,5,-1.5) (0xcc10e0); two face image ids from helpers 0xcc18ac(chestType) and 0xcc1954(chestType), paintedIndexForImageIndex each (x2), texCoordsForImageIndex x2 into [sp+0x400+8/+0x18]; DrawCube fill. (5) tail 0xcc0a54: final fillBuffer:fromIndex:matrix:width:height:depth:centerX:...:paintColor: (loc.imp.objc_msgSend with the 20+arg struct at [sp,0xe0]/stack) then count++. Float constants: 0.01 (0x3c23d70a x3), -1.5 (0xbfc00000 x5 total), pi/2 (0x3fc90fdb), -pi/2 (0xbfc90fdb x2), 0.4 (0x3ccccccd x2 / 0x3ecccccd), 0.49 (0x3efae148), 0.05 (0x3d4ccccd x2), 0.98 (0x3f7ae148), -0.18 (0xbe3851ec)..\n'),
    ),
    dict(
        name='ce_03',
        method='Chest -[addDrawItemQuadData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=13378004,
        end=13379588,
        disasm='disasm_worldtileloader_ce_03.txt',
        base_add=13378032,
        base_literal=13379584,
        boundary='ARM.exidx end 0x00cc2804 (listing bound); next ObjC IMP 0x00cc3140 Chest -[staticGeometryDodoEggCount]',
        selectors={
                 0xcc27e0: (15236476, 'count'),
                 0xcc27e4: (15236488, 'objectAtIndex:'),
                 0xcc27e8: (15236596, 'dataB'),
                 0xcc27ec: (15236452, 'itemType'),
                 0xcc27f0: (15236592, 'lastObject'),
        },
        imports={
                 0xcc27dc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcc27c8: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcc27cc: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcc27d0: (17167588, 'OBJC_IVAR_$_Chest.shelfRenderItems', 116),
                 0xcc27d8: (17167592, 'OBJC_IVAR_$_Chest.shelfItemDataBs', 132),
                 0xcc27f4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xcc27fc: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
        },
        classes={},
        instructions=[(13378004, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13379584, 'ldrshteq sp, [sb], -ip')],
        calls=[(13378404, 'blx ip'), (13378428, 'blx r2'), (13378536, 'blx r4'), (13378560, 'blx r2'), (13378584, 'blx r2'), (13378636, 'bl sym.itemTypeIsBlock_ItemType_'), (13378760, 'bl method.Vector2.operator_float__'), (13378816, 'bl method.Vector2.operator_float__'), (13378864, 'bl 0xcc10e0'), (13378908, 'bl 0xcc2804'), (13379448, 'bl 0xcc2850')],
        branches=[(13378096, 'beq', 13378136), (13378132, 'bne', 13379516), (13378160, 'bge', 13379512), (13378184, 'bge', 13379492), (13378312, 'beq', 13378600), (13378436, 'bne', 13378456), (13378452, 'b', 13379476), (13378596, 'b', 13378632), (13378608, 'bne', 13378628), (13378624, 'b', 13379476), (13378628, 'b', 13378632), (13378648, 'bne', 13379464), (13378660, 'bne', 13378680), (13378676, 'bne', 13379464), (13379488, 'b', 13378176), (13379492, 'b', 13379496), (13379508, 'b', 13378152), (13379512, 'b', 13379516)],
        semantics=('[Chest -[addDrawItemQuadData:fromIndex:]] (imp 0x00cc21d4, 396w): [census-lite] -[addDrawItemQuadData:fromIndex:] (0xcc21d4, 396w): only for chestType==2 or ==5 (cmp 2/5 at 0xcc2224/0xcc2250, else straight to return at 0xcc27bc). Runs a 2x2 shelf loop (outer [sp+0x1a4]=row, inner [sp+0x1a0]=col, each 0..<2; slot index [sp+0x1a8] = row*2+col): for each shelf slot it reads inventoryItems[slot] (non-empty -> [arr lastObject], itemType + dataB(short)); on nil/empty it falls back to cached itemType=shelfRenderItems[slot] (int[4]@116) and dataB=shelfItemDataBs[slot] (short[4]@132) at 0xcc2428. Skips blocks (itemTypeIsBlock) and itemType==0x5b with dataB!=0 (0xcc2464). Quad center = self.DynamicObject.floatPos@24 + (5*col-6, 4-5*row, -1.5) built at 0xcc2524-0xcc2530 via helper 0xcc10e0; float args 0x3f19999a (0.6) and 0x3d99999a (0.075) go to per-item dest rect builder 0xcc2804, then the 20+arg fill bridge 0xcc2850 is invoked with the assembled stack struct; its return (vertex count) accumulates into fromIndex at [sp+0x1ac] (0xcc277c)..\n'),
    ),
    dict(
        name='ce_04',
        method='Chest -[addDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=13376100,
        end=13377144,
        disasm='disasm_worldtileloader_ce_04.txt',
        base_add=13376120,
        base_literal=13377140,
        boundary='ARM.exidx end 0x00cc1e78 (listing bound); next ObjC IMP 0x00cc1e78 Chest -[staticGeometryDrawItemQuadCount]',
        selectors={},
        imports={},
        ivars={
                 0xcc1e60: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcc1e64: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0xcc1e68: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xcc1e70: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
        },
        classes={},
        instructions=[(13376100, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13377140, 'eorseq lr, sb, r4, ror r0')],
        calls=[(13376240, 'bl method.Vector.Vector_float__float__float__float_'), (13376332, 'bl 0xcc0ad4'), (13376404, 'bl sym.paintedIndexForImageIndex_int_'), (13376420, 'bl sym.texCoordsForImageIndex_int_'), (13376460, 'bl method.Vector2.operator_float__'), (13376492, 'bl method.Vector2.operator_float__'), (13376528, 'bl 0xcc10e0'), (13377092, 'bl sym.fillQuadBufferColored_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__Vector__int__int_')],
        branches=[(13376196, 'bne', 13377108), (13376288, 'beq', 13376376), (13376396, 'beq', 13376412)],
        semantics=('[Chest -[addDrawQuadData:fromIndex:forMacroPos:]] (imp 0x00cc1a64, 261w): [read] -[addDrawQuadData:fromIndex:forMacroPos:] (0xcc1a64, 261w): only chestType==5 (0xcc1abc, else return 0). Builds a 4-float Vector(1,1,1,1) at 0xcc1af0; if InteractionObject.paintColor@88 != 0 replaces it with the RGBA from the paint->color converter 0xcc0ad4 (arg r1=paintColor, r2=0) and sets a \'painted\' flag byte [sp+0x18f]=1. Image index 0x77; when painted flag set -> paintedIndexForImageIndex(0x77) (0xcc1b94); texCoordsForImageIndex -> 4 floats at [sp+0x160]. Quad center = (floatPos.x, floatPos.y + 5.0, -0.99) built via 0xcc10e0 at 0xcc1c10; struct for fillQuadBufferColored gets scale/offsets 0.5 (0x3f000000) / -0.5 (0xbf000000) and tex deltas folded (maxS=s0+s4, maxT=s2+s6); macroWorld = macroTileOwner.x*32, macroTileOwner.y*32 (0xcc1d00/0xcc1d04, lsl 5). Ends with the 20+arg fillQuadBufferColored bridge (sym.fillQuadBufferColored_float__int___GLKMatrix4__..._Vector__int__int_) and returns emitted quad count: 1 when chestType==5, else 0..\n'),
    ),
    dict(
        name='ce_05',
        method='Chest -[canBeUsedByBlockhead:]',
        types='c12@0:4@8',
        start=13359424,
        end=13360016,
        disasm='disasm_worldtileloader_ce_05.txt',
        base_add=13359440,
        base_literal=13360012,
        boundary='ARM.exidx end 0x00cbdb90 (listing bound); next ObjC IMP 0x00cbdb90 Chest -[updatePosition:]',
        selectors={
                 0xcbdb64: (15236708, 'isAdmin'),
                 0xcbdb6c: (15236712, 'isClientBlockheadBeingControlledByServer'),
                 0xcbdb74: (15236716, 'canBeUsedByBlockhead:'),
                 0xcbdb84: (15236724, 'isEqualToString:'),
                 0xcbdb88: (15236720, 'localNetID'),
        },
        imports={
                 0xcbdb60: (17151904, 'objc_msgSend'),
                 0xcbdb70: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xcbdb68: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xcbdb7c: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcbdb80: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xcbdb78: (15253232, 'OBJC_CLASS_$_Chest'),
        },
        instructions=[(13359424, 'push {r4, sl, fp, lr}'), (13360012, 'mlaseq sl, ip, r1, r2')],
        calls=[(13359504, 'blx ip'), (13359560, 'blx r2'), (13359656, 'blx r3'), (13359904, 'blx lr'), (13359940, 'blx r3')],
        branches=[(13359516, 'beq', 13359588), (13359572, 'bne', 13359588), (13359584, 'b', 13359956), (13359680, 'beq', 13359948), (13359716, 'beq', 13359792), (13359752, 'beq', 13359792), (13359788, 'bne', 13359948), (13359828, 'beq', 13359948)],
        semantics=('[Chest -[canBeUsedByBlockhead:]] (imp 0x00cbd940, 148w): [read] -[canBeUsedByBlockhead:] (0xcbd940, 148w): if [self.world isAdmin] and blockhead is NOT \'isClientBlockheadBeingControlledByServer\' -> return YES immediately (0xcbd9d8). Otherwise calls super -canBeUsedByBlockhead: via objc_msgSendSuper2 (class ref Chest at 0xcbdb78); if super returns NO -> NO. If YES and chestType is 1/5/4 (0xcbda60/0xcbda84/0xcbdaa8) and DynamicObject.ownerID@36 != nil: result = [ownerID isEqualToString:[blockhead localNetID]] (0xcbdb44). Non-owned chestTypes keep the super result. So owned chests (types 1/4/5) are per-player-netID restricted, admins bypass..\n'),
    ),
    dict(
        name='ce_06',
        method='Chest -[chestType]',
        types='i8@0:4',
        start=13359364,
        end=13359424,
        disasm='disasm_worldtileloader_ce_06.txt',
        base_add=13359372,
        base_literal=13359420,
        boundary='ARM.exidx end 0x00cbd940 (listing bound); next ObjC IMP 0x00cbd940 Chest -[canBeUsedByBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0xcbd938: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
        },
        classes={},
        instructions=[(13359364, 'sub sp, sp, 8'), (13359420, 'eorseq r2, sl, r0, ror 3')],
        calls=[],
        branches=[],
        semantics=('[Chest -[chestType]] (imp 0x00cbd904, 15w): Getter -[chestType] (0xcbd904): Apportable offset-cell getter; ivar chestType@108; plain return (15w)..\n'),
    ),
    dict(
        name='ce_07',
        method='Chest -[contentsDidChange]',
        types='v8@0:4',
        start=13353424,
        end=13354224,
        disasm='disasm_worldtileloader_ce_07.txt',
        base_add=13353440,
        base_literal=13354220,
        boundary='ARM.exidx end 0x00cbc4f0 (listing bound); next ObjC IMP 0x00cbc4f0 Chest -[update:accurateDT:isSimulation:]',
        selectors={
                 0xcbc4c4: (15236528, 'objectType'),
                 0xcbc4c8: (15236532, 'dynamicWorldChangedAtPos:objectType:'),
                 0xcbc4d0: (15236668, 'childNeedsSaving:'),
                 0xcbc4e8: (15236444, 'macroTiles'),
        },
        imports={
                 0xcbc4cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcbc4b4: (17156832, 'OBJC_IVAR_$_InteractionObject.proxyObjectOwner', 92),
                 0xcbc4b8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xcbc4c0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xcbc4d4: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcbc4d8: (17167596, 'OBJC_IVAR_$_Chest.inventoryNeedsToBeSentWithUpdate', 112),
                 0xcbc4dc: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xcbc4e4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(13353424, 'push {fp, lr}'), (13354220, 'eorseq r3, sl, ip, lsl 18')],
        calls=[(13353560, 'blx r3'), (13353648, 'bl loc.imp.objc_msgSend'), (13353684, 'bl loc.imp.objc_msgSend'), (13353900, 'bl loc.imp.objc_msgSend'), (13353944, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (13354004, 'bl loc.imp.objc_msgSend'), (13354048, 'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_'), (13354108, 'bl loc.imp.objc_msgSend'), (13354152, 'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_')],
        branches=[(13353488, 'beq', 13353568), (13353564, 'b', 13353688), (13353772, 'beq', 13353812), (13353808, 'bne', 13354156)],
        semantics=('[Chest -[contentsDidChange]] (imp 0x00cbc1d0, 200w): [read] -[contentsDidChange] (0xcbc1d0, 200w): if InteractionObject.proxyObjectOwner@92 != nil -> [proxyObjectOwner childNeedsSaving:self] (0xcbc258) else -> [self.dynamicWorld dynamicWorldChangedAtPos:self.DynamicObject.pos@16 objectType:[self objectType]] (0xcbc2d0, via loc.imp.objc_msgSend). Common tail (0xcbc2d8) sets DynamicObject.updateNeedsToBeSent@49 = 1 and inventoryNeedsToBeSentWithUpdate@112 = 1 (byte stores); for chestType==2/5 (0xcbc328/0xcbc34c) it also refreshes the draw cache via reloadDrawBlockDynamicObjectStaticGeometryForTile / ...ItemQuadsForTile / ...DodoEggQuadsForTile (0xcbc3d8/0xcbc440/0xcbc4a8) using self.pos and [world macroTiles]..\n'),
    ),
    dict(
        name='ce_08',
        method='Chest -[dealloc]',
        types='v8@0:4',
        start=13341932,
        end=13342128,
        disasm='disasm_worldtileloader_ce_08.txt',
        base_add=13341948,
        base_literal=13342124,
        boundary='ARM.exidx end 0x00cb95b0 (listing bound); next ObjC IMP 0x00cb95b0 Chest -[getSaveDict]',
        selectors={
                 0xcb9598: (15236620, 'dealloc'),
                 0xcb95a4: (15236472, 'release'),
        },
        imports={
                 0xcb9594: (17151900, 'objc_msgSendSuper2'),
                 0xcb95a0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcb95a8: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
        },
        classes={
                 0xcb959c: (15253232, 'OBJC_CLASS_$_Chest'),
        },
        instructions=[(13341932, 'push {r4, r5, r6, r7, fp, lr}'), (13342124, 'ldrshteq r6, [sl], -r0')],
        calls=[(13342048, 'blx r5'), (13342088, 'blx r2')],
        branches=[],
        semantics=('[Chest -[dealloc]] (imp 0x00cb94ec, 49w): [read] -[dealloc] (0xcb94ec, 49w): manual MRR teardown - [self.inventoryItems@100 release] via objc_msgSend then [super dealloc] through objc_msgSendSuper2 with class ref Chest (0xcb9588). No other ivars released (shelf arrays are plain C arrays)..\n'),
    ),
    dict(
        name='ce_09',
        method='Chest -[destroyItemType]',
        types='i8@0:4',
        start=13358644,
        end=13358716,
        disasm='disasm_worldtileloader_ce_09.txt',
        base_add=13358660,
        base_literal=13358712,
        boundary='ARM.exidx end 0x00cbd67c (listing bound); next ObjC IMP 0x00cbd67c Chest -[title]',
        selectors={},
        imports={},
        ivars={
                 0xcbd674: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
        },
        classes={},
        instructions=[(13358644, 'push {fp, lr}'), (13358712, 'eorseq r2, sl, r8, lsr 9')],
        calls=[(13358696, 'bl 0xcbd188')],
        branches=[],
        semantics=('[Chest -[destroyItemType]] (imp 0x00cbd634, 18w): [read] -[destroyItemType] (0xcbd634, 18w): returns the static helper 0xcbd188(chestType) - a jump table mapping chestType->itemType: 1->1065, 2->161, 3->1072, 4->1074, 5->207, 6->1104, anything else ->1043 (table 0xcbd1b4, cases at 0xcbd1cc-0xcbd214)..\n'),
    ),
    dict(
        name='ce_10',
        method='Chest -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=13349328,
        end=13349880,
        disasm='disasm_worldtileloader_ce_10.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00cbb3f8 (listing bound); next ObjC IMP 0x00cbb3f8 Chest -[moveInventoryItemsFromArray:toIndex:count:assignedIndexes:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13349328, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13349876, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        calls=[],
        branches=[],
        semantics=('[Chest -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x00cbb1d0, 138w): [read] -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] (0xcbb1d0, 138w): call-free by-value ABI re-layout: captures float arg (s0<-r2) and the two GLKMatrix4 (type encoding f8(_GLKMatrix4)12/(_GLKMatrix4)76) plus the 4 int camera bounds (140/144/148/152) and copies them through its own frame; 0 calls / 0 branches, returns void - an effectively empty -draw: override (Chest rendering goes through the static geometry entry points)..\n'),
    ),
    dict(
        name='ce_11',
        method='Chest -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=13357684,
        end=13357712,
        disasm='disasm_worldtileloader_ce_11.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00cbd2ac; body trimmed at the next IMP 0x00cbd290 Chest -[freeBlockCreationDataB]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13357684, 'sub sp, sp, 8'), (13357708, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Chest -[freeBlockCreationDataA]] (imp 0x00cbd274, 7w): [read] -[freeBlockCreationDataA] (0xcbd274, 7w): returns 0 (uxth of a zeroed register) - chests contribute no free-block creation data A..\n'),
    ),
    dict(
        name='ce_12',
        method='Chest -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=13357712,
        end=13357740,
        disasm='disasm_worldtileloader_ce_12.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00cbd2ac (listing bound); next ObjC IMP 0x00cbd2ac Chest -[remove:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13357712, 'sub sp, sp, 8'), (13357736, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Chest -[freeBlockCreationDataB]] (imp 0x00cbd290, 7w): [read] -[freeBlockCreationDataB] (0xcbd290, 7w): returns 0 - twin of freeBlockCreationDataA; no data B either..\n'),
    ),
    dict(
        name='ce_13',
        method='Chest -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=13357608,
        end=13357684,
        disasm='disasm_worldtileloader_ce_13.txt',
        base_add=13357624,
        base_literal=13357680,
        boundary='ARM.exidx end 0x00cbd274 (listing bound); next ObjC IMP 0x00cbd274 Chest -[freeBlockCreationDataA]',
        selectors={
                 0xcbd26c: (15236628, 'getSaveDict'),
        },
        imports={
                 0xcbd268: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(13357608, 'push {fp, lr}'), (13357680, 'ldrhteq r2, [sl], -r4')],
        calls=[(13357660, 'blx r3')],
        branches=[],
        semantics=('[Chest -[freeBlockCreationSaveDict]] (imp 0x00cbd228, 19w): [read] -[freeBlockCreationSaveDict] (0xcbd228, 19w): tail-calls [self getSaveDict] via objc_msgSend (sel cell 0xcbd26c) and returns its result..\n'),
    ),
    dict(
        name='ce_14',
        method='Chest -[freeblockCreationItemType]',
        types='i8@0:4',
        start=13357376,
        end=13357448,
        disasm='disasm_worldtileloader_ce_14.txt',
        base_add=13357392,
        base_literal=13357444,
        boundary='ARM.exidx end 0x00cbd188 (listing bound); next ObjC IMP 0x00cbd228 Chest -[freeBlockCreationSaveDict]',
        selectors={},
        imports={},
        ivars={
                 0xcbd180: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
        },
        classes={},
        instructions=[(13357376, 'push {fp, lr}'), (13357444, 'mlaseq sl, ip, sb, r2')],
        calls=[(13357428, 'bl 0xcbd188')],
        branches=[],
        semantics=('[Chest -[freeblockCreationItemType]] (imp 0x00cbd140, 18w): [read] -[freeblockCreationItemType] (0xcbd140, 18w): returns 0xcbd188(chestType) - same jump-table mapping as destroyItemType (1->1065, 2->161, 3->1072, 4->1074, 5->207, 6->1104, else 1043)..\n'),
    ),
    dict(
        name='ce_15',
        method='Chest -[getSaveDictIncludingInventory:]',
        types='@12@0:4c8',
        start=13342264,
        end=13345808,
        disasm='disasm_worldtileloader_ce_15.txt',
        base_add=13342280,
        base_literal=13345804,
        boundary='ARM.exidx end 0x00cba410 (listing bound); next ObjC IMP 0x00cba410 Chest -[interactionObjectType]',
        selectors={
                 0xcba38c: (15236628, 'getSaveDict'),
                 0xcba39c: (15236612, 'setObject:forKey:'),
                 0xcba3a0: (15236632, 'numberWithInt:'),
                 0xcba3b4: (15236536, 'stringWithFormat:'),
                 0xcba3cc: (15236476, 'count'),
                 0xcba3d0: (15236488, 'objectAtIndex:'),
                 0xcba3d4: (15236452, 'itemType'),
                 0xcba3d8: (15236592, 'lastObject'),
                 0xcba3dc: (15236596, 'dataB'),
                 0xcba3e0: (15236524, 'intValue'),
                 0xcba3e8: (15236468, 'objectForKey:'),
                 0xcba3ec: (15236600, 'dynamicObjectSaveDict'),
                 0xcba3f0: (15236492, 'countByEnumeratingWithState:objects:count:'),
                 0xcba3f4: (15236480, 'array'),
                 0xcba3fc: (15236636, 'loadInventoryItemsFromDiskIfNeeded'),
                 0xcba400: (15236484, 'addObject:'),
                 0xcba404: (15236568, 'saveData'),
        },
        imports={
                 0xcba388: (17151900, 'objc_msgSendSuper2'),
                 0xcba394: (16397048, '__CFConstantStringClassReference'),
                 0xcba398: (17151904, 'objc_msgSend'),
                 0xcba3b0: (16397080, '__CFConstantStringClassReference'),
                 0xcba3c4: (16397064, '__CFConstantStringClassReference'),
                 0xcba3e4: (16397128, '__CFConstantStringClassReference'),
                 0xcba408: (16397016, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xcba3a4: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcba3ac: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcba3c0: (17167588, 'OBJC_IVAR_$_Chest.shelfRenderItems', 116),
                 0xcba3c8: (17167592, 'OBJC_IVAR_$_Chest.shelfItemDataBs', 132),
        },
        classes={
                 0xcba390: (15253232, 'OBJC_CLASS_$_Chest'),
                 0xcba3a8: (15250988, 'OBJC_CLASS_$_NSNumber'),
                 0xcba3b8: (15250976, 'OBJC_CLASS_$_NSString'),
                 0xcba3f8: (15250968, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(13342264, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13345804, 'eorseq r6, sl, r4, lsr 9')],
        calls=[(13342352, 'blx lr'), (13342484, 'blx lr'), (13342520, 'blx ip'), (13342688, 'blx r2'), (13342720, 'blx r3'), (13342744, 'bl sym.imp.memset'), (13342808, 'blx lr'), (13342908, 'bl sym.imp.objc_enumerationMutation'), (13343060, 'blx r2'), (13343100, 'blx r3'), (13343120, 'bl sym.imp.memset'), (13343168, 'blx lr'), (13343268, 'bl sym.imp.objc_enumerationMutation'), (13343340, 'blx r2'), (13343420, 'blx ip'), (13343452, 'blx r3'), (13343556, 'blx ip'), (13343684, 'blx ip'), (13343776, 'blx ip'), (13344036, 'blx ip'), (13344060, 'blx r2'), (13344268, 'blx r2'), (13344316, 'blx r3'), (13344348, 'blx r3'), (13344388, 'blx lr'), (13344424, 'blx ip'), (13344444, 'blx r2'), (13344448, 'bl sym.itemTypeIsWorkbench_ItemType_'), (13344684, 'blx r2'), (13344704, 'blx r3'), (13344720, 'blx r2'), (13344768, 'blx r3'), (13344808, 'blx lr'), (13344844, 'blx ip'), (13345000, 'blx r8'), (13345028, 'blx r3'), (13345068, 'blx lr'), (13345104, 'blx ip'), (13345396, 'bl loc.imp.objc_msgSend'), (13345444, 'bl loc.imp.objc_msgSend'), (13345480, 'bl loc.imp.objc_msgSend'), (13345552, 'blx r3'), (13345592, 'blx lr'), (13345628, 'blx ip')],
        branches=[(13342532, 'beq', 13343784), (13342820, 'beq', 13343708), (13342900, 'beq', 13342912), (13343180, 'beq', 13343580), (13343260, 'beq', 13343272), (13343348, 'beq', 13343456), (13343456, 'b', 13343460), (13343484, 'blo', 13343224), (13343576, 'bne', 13343224), (13343580, 'b', 13343584), (13343584, 'b', 13343588), (13343612, 'blo', 13342864), (13343704, 'bne', 13342864), (13343708, 'b', 13343712), (13343780, 'b', 13345660), (13343816, 'beq', 13343856), (13343852, 'bne', 13345656), (13343892, 'beq', 13345160), (13343920, 'bge', 13345156), (13343944, 'bge', 13345136), (13344068, 'bne', 13344088), (13344084, 'b', 13345120), (13344460, 'beq', 13344852), (13344848, 'b', 13345108), (13345132, 'b', 13343936), (13345136, 'b', 13345140), (13345152, 'b', 13343912), (13345156, 'b', 13345652), (13345180, 'bge', 13345648), (13345644, 'b', 13345172), (13345648, 'b', 13345652), (13345652, 'b', 13345656), (13345656, 'b', 13345660)],
        semantics=('[Chest -[getSaveDictIncludingInventory:]] (imp 0x00cb9638, 886w): [census-lite] -[getSaveDictIncludingInventory:] (0xcb9638, 886w, register-traced end to end): dict = [super getSaveDict] (objc_msgSendSuper2); dict[@"chestType"] = @(chestType). If includeInventory: calls [self loadInventoryItemsFromDiskIfNeeded] then nests two NSFastEnumeration loops (objc_enumerationMutation guards, #16/#32 state blocks): arr[slotArr] where slotArr=[item saveData] for every item whose [item itemType] != 0xb; stores dict[@"saveItemSlots"] = arr. Else: nil inventory -> flat i in 0..<4 loop writes dict[@"shelfRenderItems_%d" i] = @(shelfRenderItems[i]) and dict[@"shelfItemDataBs_%d" i] = @(shelfItemDataBs[i]) from the cached ivars; non-nil inventory -> 4-iteration (2x2) loop over inventoryItems[slot]: empty slot still bumps the slot counter, non-empty slot takes [arr lastObject] and writes shelfRenderItems_i = @(itemType) plus shelfItemDataBs_i = @([[item dynamicObjectSaveDict] objectForKey:@"level"] intValue]) when itemTypeIsWorkbench, else @((unsigned short)[item dataB]). Format CFStrings: \'chestType\' 0xcba394, \'shelfRenderItems_%d\' 0xcba3c4, \'shelfItemDataBs_%d\' 0xcba3b0, \'saveItemSlots\' 0xcba408, \'level\' 0xcba3e4. Returns the dict..\n'),
    ),
    dict(
        name='ce_16',
        method='Chest -[initSubDerivedItems]',
        types='v8@0:4',
        start=13324000,
        end=13324668,
        disasm='disasm_worldtileloader_ce_16.txt',
        base_add=13324016,
        base_literal=13324664,
        boundary='ARM.exidx end 0x00cb517c (listing bound); next ObjC IMP 0x00cb517c Chest -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]',
        selectors={
                 0xcb516c: (15236444, 'macroTiles'),
        },
        imports={},
        ivars={
                 0xcb515c: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcb5160: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xcb5168: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(13324000, 'push {fp, lr}'), (13324664, 'ldrshteq sl, [sl], -ip')],
        calls=[(13324188, 'bl loc.imp.objc_msgSend'), (13324232, 'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_'), (13324292, 'bl loc.imp.objc_msgSend'), (13324336, 'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_'), (13324452, 'bl loc.imp.objc_msgSend'), (13324496, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (13324580, 'bl loc.imp.objc_msgSend'), (13324624, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_')],
        branches=[(13324060, 'beq', 13324100), (13324096, 'bne', 13324504), (13324372, 'bne', 13324500), (13324500, 'b', 13324504)],
        semantics=('[Chest -[initSubDerivedItems]] (imp 0x00cb4ee0, 167w): [read] -[initSubDerivedItems] (0xcb4ee0, 167w): if chestType->2/5: [self.world macroTiles] result + world are passed to reloadDrawBlockDynamicObjectItemQuadsForTile(pos,...) (0xcb4fc8) and reloadDrawBlockDodoEggQuadsForTile(pos,...) (0xcb5030); for chestType==5 additionally reloadDrawBlockDynamicObjectQuadsForTile (0xcb50d0). All paths then call reloadDrawBlockDynamicObjectStaticGeometryForTile(pos,...) (0xcb5150). pos comes from DynamicObject.pos@16 intpair; world from DynamicObject.world@4..\n'),
    ),
    dict(
        name='ce_17',
        method='Chest -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]',
        types='@48@0:4@8@12{?=ii}16@24@28c32@36@40@44',
        start=13324668,
        end=13328956,
        disasm='disasm_worldtileloader_ce_17.txt',
        base_add=13324684,
        base_literal=13328716,
        boundary='ARM.exidx end 0x00cb623c (listing bound); next ObjC IMP 0x00cb627c Chest -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xcb61d0: (15236448, 'initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:'),
                 0xcb61d8: (15236452, 'itemType'),
                 0xcb61e0: (15236456, 'customRules'),
                 0xcb61ec: (15236468, 'objectForKey:'),
                 0xcb61f4: (15236464, 'initWithCapacity:'),
                 0xcb61f8: (15236460, 'alloc'),
                 0xcb6200: (15236476, 'count'),
                 0xcb6204: (15236508, 'subItems'),
                 0xcb6208: (15236484, 'addObject:'),
                 0xcb620c: (15236480, 'array'),
                 0xcb6218: (15236504, 'retain'),
                 0xcb621c: (15236512, 'arrayWithArray:'),
                 0xcb6220: (15236488, 'objectAtIndex:'),
                 0xcb6224: (15236492, 'countByEnumeratingWithState:objects:count:'),
                 0xcb6228: (15236500, 'autorelease'),
                 0xcb622c: (15236496, 'initWithSaveData:'),
                 0xcb6234: (15236472, 'release'),
                 0xcb6238: (15236516, 'initSubDerivedItems'),
        },
        imports={
                 0xcb61c4: (17151968, '__stack_chk_guard'),
                 0xcb61d4: (17151904, 'objc_msgSend'),
                 0xcb61e8: (16397016, '__CFConstantStringClassReference'),
                 0xcb6214: (16397032, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xcb61dc: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcb61e4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xcb61f0: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcb6210: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xcb61cc: (15253232, 'OBJC_CLASS_$_Chest'),
                 0xcb61fc: (15250968, 'OBJC_CLASS_$_NSMutableArray'),
                 0xcb6230: (15250972, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(13324668, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13328952, 'invalid')],
        calls=[(13325008, 'bl loc.imp.objc_msgSendSuper2'), (13325132, 'blx r3'), (13325224, 'blx r2'), (13325312, 'blx r2'), (13325400, 'blx r2'), (13325488, 'blx r2'), (13325588, 'blx r3'), (13325676, 'bl loc.imp.objc_msgSend_stret'), (13325712, 'bl sym.imp.memset'), (13325832, 'blx r2'), (13325864, 'bl 0xcb623c'), (13325968, 'blx ip'), (13326012, 'blx r3'), (13326116, 'blx r3'), (13326192, 'blx r2'), (13326224, 'bl 0xcb623c'), (13326288, 'bl 0xcb623c'), (13326476, 'blx r2'), (13326520, 'blx ip'), (13326544, 'blx r3'), (13326568, 'bl sym.imp.memset'), (13326616, 'blx lr'), (13326716, 'bl sym.imp.objc_enumerationMutation'), (13326844, 'blx ip'), (13326864, 'blx r3'), (13326880, 'blx r2'), (13326904, 'blx r2'), (13326964, 'blx r3'), (13327068, 'blx ip'), (13327208, 'blx r3'), (13327264, 'blx r2'), (13327336, 'blx r3'), (13327436, 'blx lr'), (13327452, 'blx r2'), (13327548, 'blx r2'), (13327564, 'blx r2'), (13327596, 'bl 0xcb623c'), (13327664, 'blx r3'), (13327720, 'bl 0xcb623c'), (13327852, 'blx r5'), (13327884, 'blx r3'), (13327928, 'blx ip'), (13328000, 'blx r3'), (13328056, 'blx r2'), (13328120, 'blx r3'), (13328212, 'blx r2'), (13328360, 'blx r3'), (13328460, 'blx lr'), (13328476, 'blx r2'), (13328556, 'bl 0xcb623c'), (13328652, 'blx lr'), (13328696, 'blx ip'), (13328772, 'blx r2'), (13328832, 'bl sym.imp.__stack_chk_fail')],
        branches=[(13325036, 'bne', 13325052), (13325048, 'b', 13328784), (13325144, 'bne', 13325184), (13325180, 'b', 13325780), (13325232, 'bne', 13325272), (13325268, 'b', 13325776), (13325320, 'bne', 13325360), (13325356, 'b', 13325772), (13325408, 'bne', 13325448), (13325444, 'b', 13325768), (13325496, 'bne', 13325536), (13325532, 'b', 13325764), (13325600, 'bne', 13325760), (13325660, 'beq', 13325684), (13325680, 'b', 13325716), (13325724, 'bne', 13325760), (13325760, 'b', 13325764), (13325764, 'b', 13325768), (13325768, 'b', 13325772), (13325772, 'b', 13325776), (13325776, 'b', 13325780), (13326044, 'bne', 13326148), (13326144, 'b', 13328732), (13326236, 'bne', 13327484), (13326300, 'bge', 13327116), (13326628, 'beq', 13327092), (13326708, 'beq', 13326720), (13326912, 'beq', 13326968), (13326968, 'b', 13326972), (13326996, 'blo', 13326672), (13327088, 'bne', 13326672), (13327092, 'b', 13327096), (13327096, 'b', 13327100), (13327112, 'b', 13326252), (13327152, 'bne', 13327480), (13327220, 'beq', 13327276), (13327272, 'bne', 13327480), (13327348, 'beq', 13327476), (13327476, 'b', 13327480), (13327480, 'b', 13328728), (13327608, 'bne', 13328508), (13327732, 'bge', 13327948), (13327944, 'b', 13327684), (13328012, 'beq', 13328068), (13328064, 'bne', 13328504), (13328132, 'bne', 13328172), (13328168, 'b', 13328260), (13328220, 'bne', 13328256), (13328256, 'b', 13328260), (13328296, 'bne', 13328500), (13328372, 'beq', 13328500), (13328500, 'b', 13328504), (13328504, 'b', 13328724), (13328568, 'bge', 13328720), (13328712, 'b', 13328520), (13328720, 'b', 13328724), (13328724, 'b', 13328728), (13328728, 'b', 13328732), (13328816, 'bne', 13328832)],
        semantics=('[Chest -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]] (imp 0x00cb517c, 1072w): [census] -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:] (0xcb517c, 1072w / 59 br / 54 call rows): the full placement constructor. (a) [super initWithWorld:...:clientName:] (objc_msgSendSuper2, 9 args marshalled on the stack); nil -> nil. (b) chestType = 0 then derived from the placement [item itemType] via a compare chain (18 x -itemType sends): matches give chestType 1 (itemType 1065/0x429), 2, 5, 3, 6, and 0x432 (1074) -> 4 only when [self.world customRules] (objc_msgSend_stret, zeroed if world nil) has byte0 == 0; portal chests are dropped (chestType stays 0) when rules.byte0 != 0. (c) inventory: inventoryItems = [[NSMutableArray alloc] initWithCapacity:0xcb623c(chestType)] (4 slots 2/5, else 16); if [saveDict objectForKey:@"saveItemSlots"] count == slotCount -> nested fast-enum rebuild: per slot a [NSMutableArray array], items from [[InventoryItem alloc] initWithSaveData:d] + autorelease, itemType 0xb skipped; chestType==4 -> release + nil inventoryItems; when count != slotCount falls back to the placement item\'s legacy [item subItems]: per slot [NSMutableArray arrayWithArray:[subItems objectAtIndex:i]] appended (0xcb5e38). (d) owner: ownerID@36 = [[saveDict objectForKey:@"ownerID"/*or safeClientID*/] retain] with [saveDict objectForKey:@"safeClientID"] retained as fallback when ownerID == nil (two sites, 0xcb6070 and 0xcb5c70). (e) if inventoryItems == nil -> pad with [NSMutableArray array] up to slotCount (0xcb60ac-0xcb6138). (f) [self initSubDerivedItems]; return self (stack canary, __stack_chk_fail)..\n'),
    ),
    dict(
        name='ce_18',
        method='Chest -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=13332060,
        end=13335204,
        disasm='disasm_worldtileloader_ce_18.txt',
        base_add=13332076,
        base_literal=13335200,
        boundary='ARM.exidx end 0x00cb7aa4 (listing bound); next ObjC IMP 0x00cb7ac8 Chest -[inventoryDataAllowingEmpty:]',
        selectors={
                 0xcb7a04: (15236540, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0xcb7a18: (15236544, 'getBytes:length:'),
                 0xcb7a1c: (15236456, 'customRules'),
                 0xcb7a28: (15236504, 'retain'),
                 0xcb7a30: (15236468, 'objectForKey:'),
                 0xcb7a3c: (15236556, 'gzipInflate'),
                 0xcb7a40: (15236548, 'length'),
                 0xcb7a48: (15236552, 'subdataWithRange:'),
                 0xcb7a58: (15236464, 'initWithCapacity:'),
                 0xcb7a5c: (15236460, 'alloc'),
                 0xcb7a64: (15236492, 'countByEnumeratingWithState:objects:count:'),
                 0xcb7a68: (15236488, 'objectAtIndex:'),
                 0xcb7a6c: (15236484, 'addObject:'),
                 0xcb7a70: (15236480, 'array'),
                 0xcb7a74: (15236452, 'itemType'),
                 0xcb7a78: (15236500, 'autorelease'),
                 0xcb7a7c: (15236496, 'initWithSaveData:'),
                 0xcb7a84: (15236560, 'blockheads'),
                 0xcb7a8c: (15236564, 'netInteractionObjectWasLoaded:'),
                 0xcb7a90: (15236516, 'initSubDerivedItems'),
        },
        imports={
                 0xcb7a00: (17151900, 'objc_msgSendSuper2'),
                 0xcb7a0c: (17151968, '__stack_chk_guard'),
                 0xcb7a14: (17151904, 'objc_msgSend'),
                 0xcb7a2c: (16397112, '__CFConstantStringClassReference'),
                 0xcb7a38: (16397096, '__CFConstantStringClassReference'),
                 0xcb7a4c: (16397032, '__CFConstantStringClassReference'),
                 0xcb7a50: (16397016, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xcb7a10: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcb7a20: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xcb7a24: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0xcb7a34: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xcb7a54: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcb7a88: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xcb7a94: (17167588, 'OBJC_IVAR_$_Chest.shelfRenderItems', 116),
                 0xcb7a9c: (17167592, 'OBJC_IVAR_$_Chest.shelfItemDataBs', 132),
        },
        classes={
                 0xcb7a08: (15253232, 'OBJC_CLASS_$_Chest'),
                 0xcb7a60: (15250968, 'OBJC_CLASS_$_NSMutableArray'),
                 0xcb7a80: (15250972, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(13332060, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13335200, 'eorseq r8, sl, r0, lsl 25')],
        calls=[(13332228, 'blx r6'), (13332336, 'blx ip'), (13332460, 'bl loc.imp.objc_msgSend_stret'), (13332496, 'bl sym.imp.memset'), (13332740, 'bl loc.imp.objc_msgSend'), (13332808, 'bl loc.imp.objc_msgSend'), (13332832, 'blx r2'), (13332836, 'bl 0xcb7aa4'), (13332964, 'blx ip'), (13332980, 'blx r2'), (13333024, 'blx r3'), (13333040, 'blx r2'), (13333252, 'blx lr'), (13333268, 'blx r2'), (13333352, 'blx r3'), (13333428, 'blx r2'), (13333460, 'bl 0xcb623c'), (13333532, 'blx ip'), (13333604, 'bl 0xcb623c'), (13333792, 'blx r2'), (13333836, 'blx ip'), (13333860, 'blx r3'), (13333884, 'bl sym.imp.memset'), (13333932, 'blx lr'), (13334032, 'bl sym.imp.objc_enumerationMutation'), (13334160, 'blx ip'), (13334180, 'blx r3'), (13334196, 'blx r2'), (13334220, 'blx r2'), (13334280, 'blx r3'), (13334384, 'blx ip'), (13334556, 'blx r2'), (13334580, 'bl sym.imp.memset'), (13334628, 'blx lr'), (13334728, 'bl sym.imp.objc_enumerationMutation'), (13334808, 'blx ip'), (13334908, 'blx ip'), (13334976, 'blx r2'), (13335036, 'bl sym.imp.__stack_chk_fail')],
        branches=[(13332256, 'bne', 13332272), (13332268, 'b', 13334988), (13332384, 'bne', 13332544), (13332444, 'beq', 13332468), (13332464, 'b', 13332500), (13332508, 'beq', 13332544), (13332564, 'bge', 13332680), (13332676, 'b', 13332556), (13333088, 'bne', 13333128), (13333124, 'b', 13334440), (13333164, 'bne', 13333292), (13333372, 'beq', 13334436), (13333616, 'bge', 13334432), (13333944, 'beq', 13334408), (13334024, 'beq', 13334036), (13334228, 'beq', 13334284), (13334284, 'b', 13334288), (13334312, 'blo', 13333988), (13334404, 'bne', 13333988), (13334408, 'b', 13334412), (13334412, 'b', 13334416), (13334428, 'b', 13333568), (13334432, 'b', 13334436), (13334436, 'b', 13334440), (13334640, 'beq', 13334932), (13334720, 'beq', 13334732), (13334836, 'blo', 13334684), (13334928, 'bne', 13334684), (13334932, 'b', 13334936), (13335020, 'bne', 13335036)],
        semantics=('[Chest -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x00cb6e5c, 786w): [census-lite] -[initWithWorld:dynamicWorld:cache:netData:] (0xcb6e5c, 786w): [super initWithWorld:dynamicWorld:cache:netData:] (objc_msgSendSuper2, class Chest); nil -> nil. [netData getBytes:&hdr length:0x40]: chestType = hdr[0x38] (0xcb6f88); if chestType==4 and the world\'s [world customRules] byte0 == 0 -> chestType = 0 (portal chest disabled). Copies hdr[0x28..0x30] u16[4] -> shelfRenderItems, hdr[0x30..0x38] u16[4] -> shelfItemDataBs (loop 0..<4, 0xcb70c4). rest=[netData subdataWithRange:NSMakeRange(0x40,len-0x40)] -> gzipInflate -> 0xcb7aa4 plist dict; ownerID=[dict objectForKey:@"ownerID"] retained -> DynamicObject.ownerID@36; ownerName=[dict objectForKey:@"ownerName"] retained -> InteractionObject.ownerName@84 (0xcb7244). chestType==4 -> inventoryItems=nil; else: ownerID==nil -> ownerID=[dict objectForKey:@"safeClientID"] retained (0xcb7328); dict[@"saveItemSlots"] != nil -> inventoryItems=[[NSMutableArray alloc] initWithCapacity:0xcb623c(chestType)] and per slot i in 0..<slotCount: sub=[NSMutableArray array], items appended from [[InventoryItem alloc] initWithSaveData:d] + autorelease skipping itemType 0xb. Then notifies [self.dynamicWorld blockheads] each [b netInteractionObjectWasLoaded:self] (0xcb7918), calls [self initSubDerivedItems], returns self (stack canary checked, __stack_chk_fail on mismatch)..\n'),
    ),
    dict(
        name='ce_19',
        method='Chest -[interactionObjectType]',
        types='S8@0:4',
        start=13345808,
        end=13345836,
        disasm='disasm_worldtileloader_ce_19.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00cba42c (listing bound); next ObjC IMP 0x00cba42c Chest -[remoteUpdate:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13345808, 'sub sp, sp, 8'), (13345832, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Chest -[interactionObjectType]] (imp 0x00cba410, 7w): [read] -[interactionObjectType] (0xcba410, 7w): returns the constant 2 (uxth of #2) - the InteractionObjectType id for chest..\n'),
    ),
    dict(
        name='ce_20',
        method='Chest -[interactionRenderItemType]',
        types='i8@0:4',
        start=13384144,
        end=13384216,
        disasm='disasm_worldtileloader_ce_20.txt',
        base_add=13384160,
        base_literal=13384212,
        boundary='ARM.exidx end 0x00cc3bbc; body trimmed at the next IMP 0x00cc3a18 Chest -[paint:]',
        selectors={},
        imports={},
        ivars={
                 0xcc3a10: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
        },
        classes={},
        instructions=[(13384144, 'push {fp, lr}'), (13384212, 'eorseq ip, sb, ip, lsl 2')],
        calls=[(13384196, 'bl 0xcbd188')],
        branches=[],
        semantics=('[Chest -[interactionRenderItemType]] (imp 0x00cc39d0, 18w): [read] -[interactionRenderItemType] (0xcc39d0, 18w): returns 0xcbd188(chestType) - third user of the same chestType->ItemType jump table (1->1065, 2->161, 3->1072, 4->1074, 5->207, 6->1104, else 1043)..\n'),
    ),
    dict(
        name='ce_21',
        method='Chest -[inventoryChanged]',
        types='c8@0:4',
        start=13386172,
        end=13386232,
        disasm='disasm_worldtileloader_ce_21.txt',
        base_add=13386180,
        base_literal=13386228,
        boundary='ARM.exidx end 0x00cc41f8 (listing bound); next ObjC IMP 0x00cc5760 NewBlockheadUI -[randomizeForGender:allowNameChange:]',
        selectors={},
        imports={},
        ivars={
                 0xcc41f0: (17167600, 'OBJC_IVAR_$_Chest.inventoryChanged', 104),
        },
        classes={},
        instructions=[(13386172, 'sub sp, sp, 8'), (13386228, 'eorseq fp, sb, r8, lsr 18')],
        calls=[],
        branches=[],
        semantics=('[Chest -[inventoryChanged]] (imp 0x00cc41bc, 15w): [read] -[inventoryChanged] (0xcc41bc, 15w): boolean getter for inventoryChanged@104 (ldrsb, offset-cell form)..\n'),
    ),
    dict(
        name='ce_22',
        method='Chest -[inventoryDataAllowingEmpty:]',
        types='@12@0:4c8',
        start=13335240,
        end=13336532,
        disasm='disasm_worldtileloader_ce_22.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00cb7fd4 (listing bound); next ObjC IMP 0x00cb8140 Chest -[updateInventoryWithData:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13335240, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13336528, 'eorseq r8, sl, r4, lsl r0')],
        calls=[(13335444, 'blx r2'), (13335468, 'bl sym.imp.memset'), (13335532, 'blx lr'), (13335632, 'bl sym.imp.objc_enumerationMutation'), (13335784, 'blx r2'), (13335824, 'blx r3'), (13335844, 'bl sym.imp.memset'), (13335892, 'blx lr'), (13335992, 'bl sym.imp.objc_enumerationMutation'), (13336100, 'blx ip'), (13336132, 'blx r3'), (13336232, 'blx ip'), (13336360, 'blx ip'), (13336428, 'bl 0xcb7fd4'), (13336468, 'blx r3')],
        branches=[(13335308, 'bne', 13335324), (13335320, 'b', 13336484), (13335544, 'beq', 13336384), (13335624, 'beq', 13335636), (13335904, 'beq', 13336256), (13335984, 'beq', 13335996), (13336160, 'blo', 13335948), (13336252, 'bne', 13335948), (13336256, 'b', 13336260), (13336260, 'b', 13336264), (13336288, 'blo', 13335588), (13336380, 'bne', 13335588), (13336384, 'b', 13336388), (13336396, 'bne', 13336424), (13336408, 'bne', 13336424), (13336420, 'b', 13336484)],
        semantics=('[Chest -[inventoryDataAllowingEmpty:]] (imp 0x00cb7ac8, 323w): [census-lite] -[inventoryDataAllowingEmpty:] (0xcb7ac8, 323w): inventoryItems==nil -> return nil. Else builds a nested NSMutableArray: outer enum over inventoryItems, a sub=[NSMutableArray array] per slot array, inner enum appending [item saveData] for every item (no itemType filter here; sets a \'sawItems\' flag byte [fp-0x2a]=1 each hit), sub added to the outer array. If sawItems==0 and allowingEmpty arg==0 -> return nil; else arr -> helper 0xcb7fd4 = [NSPropertyListSerialization dataWithPropertyList:arr format:100 (binary) options:0 error:&err] (nil-safe wrapper, with @catch logging CFString \'Failed to load plist due to exception in dataFromPropertyList. Exception:\'%@\' (reason: \'%@\')\' via exception name/reason) -> [data gzipDeflate] (sel 0xcb7fcc) -> returned. This is the chest inventory -> binary plist -> gzip wire form..\n'),
    ),
    dict(
        name='ce_23',
        method='Chest -[inventoryItems]',
        types='@8@0:4',
        start=13384964,
        end=13385252,
        disasm='disasm_worldtileloader_ce_23.txt',
        base_add=13384980,
        base_literal=13385248,
        boundary='ARM.exidx end 0x00cc3e24 (listing bound); next ObjC IMP 0x00cc3e24 Chest -[occupiesNormalContents]',
        selectors={
                 0xcc3e10: (15236636, 'loadInventoryItemsFromDiskIfNeeded'),
                 0xcc3e14: (15236748, 'portalChestInventoryItems'),
                 0xcc3e18: (15236744, 'portalChestManager'),
        },
        imports={
                 0xcc3e0c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcc3e04: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcc3e08: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcc3e1c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(13384964, 'push {r4, sl, fp, lr}'), (13385248, 'ldrsbteq fp, [sb], -r8')],
        calls=[(13385108, 'blx ip'), (13385124, 'blx r2'), (13385180, 'blx r2')],
        branches=[(13385024, 'bne', 13385136), (13385132, 'b', 13385208)],
        semantics=('[Chest -[inventoryItems]] (imp 0x00cc3d04, 72w): [read] -[inventoryItems] (0xcc3d04, 72w): if chestType==4 -> [[self.world portalChestManager] portalChestInventoryItems]; else [self loadInventoryItemsFromDiskIfNeeded] then return the inventoryItems@100 ivar..\n'),
    ),
    dict(
        name='ce_24',
        method='Chest -[isPaintable]',
        types='c8@0:4',
        start=13384636,
        end=13384664,
        disasm='disasm_worldtileloader_ce_24.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00cc3bd8 (listing bound); next ObjC IMP 0x00cc3bd8 Chest -[loadInventoryItemsFromDiskIfNeeded]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13384636, 'sub sp, sp, 8'), (13384660, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Chest -[isPaintable]] (imp 0x00cc3bbc, 7w): [read] -[isPaintable] (0xcc3bbc, 7w): returns YES (sxtb of #1)..\n'),
    ),
    dict(
        name='ce_25',
        method='Chest -[loadInventoryItemsFromDiskIfNeeded]',
        types='v8@0:4',
        start=13384664,
        end=13384964,
        disasm='disasm_worldtileloader_ce_25.txt',
        base_add=13384680,
        base_literal=13384960,
        boundary='ARM.exidx end 0x00cc3d04 (listing bound); next ObjC IMP 0x00cc3d04 Chest -[inventoryItems]',
        selectors={
                 0xcc3cf4: (15236584, 'updateInventoryWithData:'),
                 0xcc3cf8: (15236760, 'loadLocalInventoryDataForChest:'),
        },
        imports={
                 0xcc3cf0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcc3ce4: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcc3ce8: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcc3cec: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xcc3cfc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(13384664, 'push {r4, sl, fp, lr}'), (13384960, 'eorseq fp, sb, r4, lsl 30')],
        calls=[(13384892, 'blx ip'), (13384920, 'blx r3')],
        branches=[(13384728, 'bne', 13384924), (13384764, 'beq', 13384924), (13384800, 'bne', 13384924)],
        semantics=('[Chest -[loadInventoryItemsFromDiskIfNeeded]] (imp 0x00cc3bd8, 75w): [read] -[loadInventoryItemsFromDiskIfNeeded] (0xcc3bd8, 75w): returns early if inventoryItems@100 != nil, or chestType==4 (portal chest), or DynamicObject.isNet@52 != 0; otherwise data = [self.dynamicWorld loadLocalInventoryDataForChest:self] then [self updateInventoryWithData:data]..\n'),
    ),
    dict(
        name='ce_26',
        method='Chest -[moveInventoryItemsFromArray:toIndex:count:]',
        types='i20@0:4@8i12i16',
        start=13353216,
        end=13353424,
        disasm='disasm_worldtileloader_ce_26.txt',
        base_add=13353308,
        base_literal=13353420,
        boundary='ARM.exidx end 0x00cbc1d0 (listing bound); next ObjC IMP 0x00cbc1d0 Chest -[contentsDidChange]',
        selectors={
                 0xcbc1c8: (15236656, 'moveInventoryItemsFromArray:toIndex:count:assignedIndexes:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(13353216, 'push {r4, sl, fp, lr}'), (13353420, 'mlaseq sl, r0, sb, r3')],
        calls=[(13353280, 'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__tree_std::__1::less_int__const_'), (13353336, 'bl loc.imp.objc_msgSend'), (13353360, 'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__'), (13353400, 'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__'), (13353412, 'bl sym.imp._Unwind_Resume')],
        branches=[(13353344, 'b', 13353348)],
        semantics=('[Chest -[moveInventoryItemsFromArray:toIndex:count:]] (imp 0x00cbc100, 52w): [read] -[moveInventoryItemsFromArray:toIndex:count:] (0xcbc100, 52w): thin wrapper - builds a stack std::__1::set<int> (assignedIndexes), calls -moveInventoryItemsFromArray:toIndex:count:assignedIndexes: with (array, toIndex, count, &set) via stack args (count at [sp], &set at [sp+4]), destroys the set (0xcbc190) and returns the call\'s result. Unwind landing pad resumes via _Unwind_Resume..\n'),
    ),
    dict(
        name='ce_27',
        method='Chest -[moveInventoryItemsFromArray:toIndex:count:assignedIndexes:]',
        types='i24@0:4@8i12i16^{set<int, std::__1::less<int>, std::__1::allocator<int> >={__tree<int, std::__1::less<int>, std::__1::allocator<int> >=^{__tree_node<int, void *>}{__compressed_pair<std::__1::__tree_end_node<std::__1::__tree_node_base<void *> *>, std::__1::allocator<std::__1::__tree_node<int, void *> > >={__tree_end_node<std::__1::__tree_node_base<void *> *>=^{__tree_node_base<void *>}}}{__compressed_pair<unsigned long, std::__1::less<int> >=L}}}20',
        start=13349880,
        end=13353216,
        disasm='disasm_worldtileloader_ce_27.txt',
        base_add=13349896,
        base_literal=13353212,
        boundary='ARM.exidx end 0x00cbc100 (listing bound); next ObjC IMP 0x00cbc100 Chest -[moveInventoryItemsFromArray:toIndex:count:]',
        selectors={
                 0xcbc0c4: (15236476, 'count'),
                 0xcbc0c8: (15236452, 'itemType'),
                 0xcbc0cc: (15236488, 'objectAtIndex:'),
                 0xcbc0d0: (15236492, 'countByEnumeratingWithState:objects:count:'),
                 0xcbc0d8: (15236596, 'dataB'),
                 0xcbc0dc: (15236656, 'moveInventoryItemsFromArray:toIndex:count:assignedIndexes:'),
                 0xcbc0e0: (15236660, 'contentsDidChange'),
                 0xcbc0e8: (15236664, 'reportAchievementWithIdentifier:'),
                 0xcbc0f0: (15236652, 'removeObjectAtIndex:'),
                 0xcbc0f4: (15236484, 'addObject:'),
        },
        imports={
                 0xcbc0c0: (17151904, 'objc_msgSend'),
                 0xcbc0e4: (16397160, '__CFConstantStringClassReference'),
                 0xcbc0f8: (16397144, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xcbc0bc: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcbc0d4: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcbc0ec: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(13349880, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13353212, 'eorseq r4, sl, r4, ror 13')],
        calls=[(13350004, 'bl sym.imp.NSLog'), (13350084, 'blx r2'), (13350200, 'blx lr'), (13350216, 'blx r2'), (13350236, 'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_'), (13350352, 'bl sym.imp.memset'), (13350416, 'blx lr'), (13350516, 'bl sym.imp.objc_enumerationMutation'), (13350588, 'blx r2'), (13350640, 'blx r2'), (13350728, 'blx r4'), (13350744, 'blx r2'), (13350788, 'blx r3'), (13350804, 'blx r2'), (13350904, 'blx r5'), (13350920, 'blx r2'), (13350956, 'blx r3'), (13350972, 'blx r2'), (13351004, 'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_'), (13351144, 'blx ip'), (13351288, 'bl sym.imp.memset'), (13351352, 'blx lr'), (13351452, 'bl sym.imp.objc_enumerationMutation'), (13351524, 'blx r2'), (13351656, 'blx ip'), (13351828, 'blx r5'), (13351852, 'blx r2'), (13351880, 'blx r3'), (13351896, 'blx r2'), (13351992, 'blx ip'), (13352008, 'blx r2'), (13352108, 'blx r5'), (13352124, 'blx r2'), (13352160, 'blx r3'), (13352176, 'blx r2'), (13352208, 'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_'), (13352276, 'blx r2'), (13352332, 'blx r2'), (13352464, 'blx r2'), (13352596, 'blx r4'), (13352636, 'blx r3'), (13352660, 'blx r3'), (13352796, 'blx ip'), (13352856, 'blx r2'), (13352968, 'blx ip'), (13353028, 'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__insert_unique_int_const_')],
        branches=[(13349988, 'bne', 13350020), (13350016, 'b', 13353136), (13350028, 'bne', 13350044), (13350040, 'b', 13353136), (13350092, 'bne', 13350108), (13350104, 'b', 13353136), (13350116, 'beq', 13351692), (13350248, 'beq', 13351176), (13350428, 'beq', 13351168), (13350508, 'beq', 13350520), (13350596, 'bls', 13351036), (13350648, 'bhs', 13351036), (13350816, 'bne', 13351032), (13351016, 'beq', 13351032), (13351028, 'b', 13351172), (13351032, 'b', 13351036), (13351072, 'blo', 13350472), (13351164, 'bne', 13350472), (13351168, 'b', 13351172), (13351172, 'b', 13351176), (13351184, 'bne', 13351688), (13351364, 'beq', 13351680), (13351444, 'beq', 13351456), (13351532, 'bne', 13351548), (13351544, 'b', 13351684), (13351584, 'blo', 13351408), (13351676, 'bne', 13351408), (13351680, 'b', 13351684), (13351684, 'b', 13351688), (13351688, 'b', 13351692), (13351700, 'bne', 13351716), (13351712, 'b', 13353136), (13351912, 'ble', 13352236), (13352020, 'bne', 13352224), (13352220, 'bne', 13352236), (13352232, 'b', 13353136), (13352288, 'bhs', 13352340), (13352384, 'bge', 13352400), (13352396, 'b', 13352408), (13352504, 'bge', 13352680), (13352676, 'b', 13352492), (13352688, 'beq', 13352812), (13352700, 'ble', 13352812), (13352716, 'bge', 13352812), (13352884, 'bne', 13352972), (13352980, 'ble', 13353128)],
        semantics=('[Chest -[moveInventoryItemsFromArray:toIndex:count:assignedIndexes:]] (imp 0x00cbb3f8, 834w): [census-lite] -[moveInventoryItemsFromArray:toIndex:count:assignedIndexes:] (0xcbb3f8, 834w): guards - chestType==4 logs NSLog CFString \'This function should not be called on portal chests.\' and returns 0 (0xcbb468); empty array (count==0) returns 0; count==-1 sets \'all\' flag [fp-0x6d]. All-mode pre-pass: srcItem=[array objectAtIndex:0]; if itemTypeIsStackable(itemType,0,0) scan inventoryItems for a merge target - first slot with 0 < [slot count] < 99 whose top (index 0) item has the same itemType and itemTypeIsStackable(itemType, uxth(dest top dataB), uxth(src dataB)); if none (toIndex==-1) a second scan picks the first slot with count==0; still -1 -> return 0. Move phase (0xcbbb24): dest=inventoryItems[toIndex], destCount=[dest count]; when destCount>0 requires same itemType + dataB-stackable else return 0; count=min(count,[array count]); space=99-destCount; moveNow=min(count,space); loop [dest addObject:[array objectAtIndex:K]] + [array removeObjectAtIndex:K] with K=[array count]-moveNow (moves the tail block, 0xcbbe2c-0xcbbe e4). All-mode remainder: recursive self-call with toIndex=-1, count-moveNow, same assignedIndexes set (0xcbbf5c), total = moveNow + result. Then [self contentsDidChange]; chestType==2 -> [self.world reportAchievementWithIdentifier:@"grp.shelf"] (0xcbc008); if total>0 -> assignedIndexes->insert(toIndex) via std::__1::__tree<int>::__insert_unique at 0xcbc044; returns items moved. 99 = per-slot stack cap (0x63)..\n'),
    ),
    dict(
        name='ce_28',
        method='Chest -[occupiesNormalContents]',
        types='c8@0:4',
        start=13385252,
        end=13385280,
        disasm='disasm_worldtileloader_ce_28.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00cc3e40 (listing bound); next ObjC IMP 0x00cc3e40 Chest -[removeItemIfAvailable:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13385252, 'sub sp, sp, 8'), (13385276, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Chest -[occupiesNormalContents]] (imp 0x00cc3e24, 7w): [read] -[occupiesNormalContents] (0xcc3e24, 7w): returns YES (sxtb of #1)..\n'),
    ),
    dict(
        name='ce_29',
        method='Chest -[paint:]',
        types='v12@0:4S8',
        start=13384216,
        end=13384636,
        disasm='disasm_worldtileloader_ce_29.txt',
        base_add=13384232,
        base_literal=13384632,
        boundary='ARM.exidx end 0x00cc3bbc (listing bound); next ObjC IMP 0x00cc3bbc Chest -[isPaintable]',
        selectors={
                 0xcc3ba0: (15236444, 'macroTiles'),
                 0xcc3bb0: (15236528, 'objectType'),
                 0xcc3bb4: (15236532, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={},
        ivars={
                 0xcc3b8c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xcc3b90: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0xcc3b98: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xcc3b9c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xcc3ba4: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xcc3bac: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(13384216, 'push {fp, lr}'), (13384632, 'eorseq ip, sb, r4, asr 1')],
        calls=[(13384352, 'bl loc.imp.objc_msgSend'), (13384396, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (13384540, 'bl loc.imp.objc_msgSend'), (13384576, 'bl loc.imp.objc_msgSend')],
        branches=[(13384432, 'bne', 13384580)],
        semantics=('[Chest -[paint:]] (imp 0x00cc3a18, 105w): [read] -[paint:] (0xcc3a18, 105w): stores the unsigned-short arg into InteractionObject.paintColor@88 (strh); reloads static geometry via [self.world macroTiles] + reloadDrawBlockDynamicObjectStaticGeometryForTile(pos,...); if !DynamicObject.isNet@52 sets DynamicObject.updateNeedsToBeSent@49 = 1 and notifies [self.dynamicWorld dynamicWorldChangedAtPos:pos objectType:[self objectType]]..\n'),
    ),
    dict(
        name='ce_30',
        method='Chest -[remoteInventoryDataRecieved:]',
        types='v12@0:4@8',
        start=13338804,
        end=13338888,
        disasm='disasm_worldtileloader_ce_30.txt',
        base_add=13338820,
        base_literal=13338884,
        boundary='ARM.exidx end 0x00cb8908 (listing bound); next ObjC IMP 0x00cb8908 Chest -[updateNetDataForClient:]',
        selectors={
                 0xcb8900: (15236584, 'updateInventoryWithData:'),
        },
        imports={
                 0xcb88fc: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(13338804, 'push {fp, lr}'), (13338884, 'eorseq r7, sl, r8, lsr 4')],
        calls=[(13338864, 'blx ip')],
        branches=[],
        semantics=('[Chest -[remoteInventoryDataRecieved:]] (imp 0x00cb88b4, 21w): [read] -[remoteInventoryDataRecieved:] (0xcb88b4, 21w): tail-calls [self updateInventoryWithData:arg]..\n'),
    ),
    dict(
        name='ce_31',
        method='Chest -[remoteUpdate:]',
        types='v12@0:4@8',
        start=13345836,
        end=13349328,
        disasm='disasm_worldtileloader_ce_31.txt',
        base_add=13345852,
        base_literal=13349324,
        boundary='ARM.exidx end 0x00cbb1d0 (listing bound); next ObjC IMP 0x00cbb1d0 Chest -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0xcbb110: (15236640, 'remoteUpdate:'),
                 0xcbb120: (15236544, 'getBytes:length:'),
                 0xcbb130: (15236444, 'macroTiles'),
                 0xcbb140: (15236504, 'retain'),
                 0xcbb148: (15236468, 'objectForKey:'),
                 0xcbb14c: (15236472, 'release'),
                 0xcbb158: (15236556, 'gzipInflate'),
                 0xcbb15c: (15236548, 'length'),
                 0xcbb164: (15236552, 'subdataWithRange:'),
                 0xcbb16c: (15236644, 'removeAllObjects'),
                 0xcbb17c: (15236492, 'countByEnumeratingWithState:objects:count:'),
                 0xcbb180: (15236488, 'objectAtIndex:'),
                 0xcbb184: (15236484, 'addObject:'),
                 0xcbb188: (15236480, 'array'),
                 0xcbb190: (15236452, 'itemType'),
                 0xcbb194: (15236500, 'autorelease'),
                 0xcbb198: (15236496, 'initWithSaveData:'),
                 0xcbb19c: (15236460, 'alloc'),
                 0xcbb1b0: (15236648, 'sendChestInventoryForChest:toClientOwningBlockheadWithID:'),
                 0xcbb1b4: (15236636, 'loadInventoryItemsFromDiskIfNeeded'),
        },
        imports={
                 0xcbb10c: (17151900, 'objc_msgSendSuper2'),
                 0xcbb11c: (17151904, 'objc_msgSend'),
                 0xcbb144: (16397112, '__CFConstantStringClassReference'),
                 0xcbb154: (16397096, '__CFConstantStringClassReference'),
                 0xcbb168: (16397016, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xcbb0fc: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xcbb100: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0xcbb104: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
                 0xcbb118: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcbb124: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xcbb12c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xcbb138: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xcbb13c: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0xcbb150: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xcbb170: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcbb1a4: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xcbb1bc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xcbb1c0: (17167588, 'OBJC_IVAR_$_Chest.shelfRenderItems', 116),
                 0xcbb1c8: (17167592, 'OBJC_IVAR_$_Chest.shelfItemDataBs', 132),
        },
        classes={
                 0xcbb114: (15253232, 'OBJC_CLASS_$_Chest'),
                 0xcbb18c: (15250968, 'OBJC_CLASS_$_NSMutableArray'),
                 0xcbb1a0: (15250972, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(13345836, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13349324, 'ldrhteq r5, [sl], -r0')],
        calls=[(13346092, 'blx r3'), (13346160, 'blx ip'), (13346484, 'bl loc.imp.objc_msgSend'), (13346528, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (13346644, 'bl loc.imp.objc_msgSend'), (13346688, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (13346796, 'bl loc.imp.objc_msgSend'), (13346864, 'bl loc.imp.objc_msgSend'), (13346888, 'blx r2'), (13346892, 'bl 0xcb7aa4'), (13347076, 'blx ip'), (13347100, 'blx r3'), (13347116, 'blx r2'), (13347172, 'blx ip'), (13347196, 'blx r3'), (13347212, 'blx r2'), (13347324, 'blx r3'), (13347420, 'blx r3'), (13347472, 'bl 0xcb623c'), (13347660, 'blx r2'), (13347704, 'blx ip'), (13347728, 'blx r3'), (13347752, 'bl sym.imp.memset'), (13347800, 'blx lr'), (13347900, 'bl sym.imp.objc_enumerationMutation'), (13348028, 'blx ip'), (13348048, 'blx r3'), (13348064, 'blx r2'), (13348088, 'blx r2'), (13348148, 'blx r3'), (13348252, 'blx ip'), (13348460, 'bl loc.imp.objc_msgSend'), (13348504, 'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_'), (13348564, 'bl loc.imp.objc_msgSend'), (13348608, 'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_'), (13348724, 'bl loc.imp.objc_msgSend'), (13348768, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (13349016, 'bl loc.imp.objc_msgSend'), (13349104, 'bl loc.imp.objc_msgSend')],
        branches=[(13345928, 'beq', 13345976), (13345972, 'b', 13345996), (13345992, 'b', 13345996), (13346188, 'beq', 13346228), (13346224, 'bne', 13346368), (13346248, 'bge', 13346364), (13346360, 'b', 13346240), (13346364, 'b', 13346368), (13346404, 'beq', 13346696), (13346564, 'bne', 13346692), (13346692, 'b', 13346696), (13346732, 'bne', 13348788), (13347260, 'beq', 13348784), (13347344, 'beq', 13348780), (13347484, 'bge', 13348300), (13347812, 'beq', 13348276), (13347892, 'beq', 13347904), (13348096, 'beq', 13348152), (13348152, 'b', 13348156), (13348180, 'blo', 13347856), (13348272, 'bne', 13347856), (13348276, 'b', 13348280), (13348280, 'b', 13348284), (13348296, 'b', 13347436), (13348332, 'beq', 13348372), (13348368, 'bne', 13348776), (13348644, 'bne', 13348772), (13348772, 'b', 13348776), (13348776, 'b', 13348780), (13348780, 'b', 13348784), (13348784, 'b', 13348788), (13348820, 'bne', 13349108), (13348880, 'beq', 13349108), (13348884, 'b', 13348888), (13348928, 'beq', 13349108), (13348932, 'b', 13348936), (13348968, 'beq', 13349108)],
        semantics=('[Chest -[remoteUpdate:]] (imp 0x00cba42c, 873w): [census-lite] -[remoteUpdate:] (0xcba42c, 873w): saves old paintColor@88 (u16) and old remoteBlockheadInUseUniqueID@72 pair (zeroed when !isInUse); [super remoteUpdate:data] (objc_msgSendSuper2). [data getBytes:&hdr length:0x40] - header layout: hdr[0x28..0x30) = 4 x u16 shelfRenderItems, hdr[0x30..0x38) = 4 x u16 shelfItemDataBs (copied into the ivars only for chestType 2/5, loop 0..<4 at 0xcba5c0). If paintColor changed: static-geometry reload; for chestType==5 also reloadDrawBlockDynamicObjectQuadsForTile (0xcba780). When currentBlockhead@56 == nil: rest = [data subdataWithRange:NSMakeRange(0x40, len-0x40)] -> [rest gzipInflate] -> 0xcb7aa4 -> 0xcc5494 = nil-safe [NSPropertyListSerialization propertyListWithData:... options:0 format:error:&e] (with @catch); dict keys ownerID/ownerName are retained into DynamicObject.ownerID@36 and InteractionObject.ownerName@84 (release-then-store); chestType!=4 and dict["saveItemSlots"] != nil: [inventoryItems removeAllObjects] then rebuild slot arrays: N = 0xcb623c(chestType) (chestType 2/5 -> 4 slots, else 16) outer loop over the plist array, per slot a [NSMutableArray array] added to inventoryItems, inner loop: item = [[InventoryItem alloc] initWithSaveData:d] + autorelease, appended unless [item itemType]==0xb (0xcbad34). Then for chestType 2/5: reload item quads + dodo egg quads (+ DynamicObjectQuads when 5). Common tail (0xcbafb4): if !DynamicObject.isNet@52 and the blockhead-in-use ID changed (old pair != new remoteBlockheadInUseUniqueID@72), new ID != 0 and chestType!=4 -> [self loadInventoryItemsFromDiskIfNeeded]; [self.dynamicWorld sendChestInventoryForChest:self toClientOwningBlockheadWithID:(saved pair)] (0xcbb0f0). Helper facts: 0xcb623c = slotCountForChestType (2/5->4 else 16); 0xcb7aa4 = plist decode wrapper..\n'),
    ),
    dict(
        name='ce_32',
        method='Chest -[remove:]',
        types='v12@0:4@8',
        start=13357740,
        end=13358372,
        disasm='disasm_worldtileloader_ce_32.txt',
        base_add=13357756,
        base_literal=13358368,
        boundary='ARM.exidx end 0x00cbd524 (listing bound); next ObjC IMP 0x00cbd524 Chest -[setNeedsRemoved:]',
        selectors={
                 0xcbd4f8: (15236688, 'isNet'),
                 0xcbd508: (15236692, 'stopInteracting'),
                 0xcbd50c: (15236700, 'setNeedsRemoved:'),
                 0xcbd510: (15236696, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
        },
        imports={
                 0xcbd4f4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcbd4e8: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xcbd4ec: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xcbd4f0: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xcbd4fc: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xcbd500: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
                 0xcbd514: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xcbd518: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xcbd51c: (17156820, 'OBJC_IVAR_$_InteractionObject.needsToBeRemovedWhenInteractionEnds', 96),
        },
        classes={},
        instructions=[(13357740, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13358368, 'eorseq r2, sl, r0, lsr r8')],
        calls=[(13357944, 'blx r2'), (13358104, 'blx r2'), (13358272, 'blx lr'), (13358300, 'blx r3')],
        branches=[(13357804, 'bne', 13357844), (13357840, 'beq', 13357848), (13357844, 'b', 13358304), (13357880, 'beq', 13358112), (13357956, 'bne', 13358008), (13358000, 'beq', 13358044), (13358004, 'b', 13358008), (13358040, 'b', 13358304), (13358108, 'b', 13358112)],
        semantics=('[Chest -[remove:]] (imp 0x00cbd2ac, 158w): [read] -[remove:] (0xcbd2ac, 158w): no-op unless !DynamicObject.needsRemoved@48 && !DynamicObject.isNet@52. If InteractionObject.isInUse@68: when [currentBlockhead@56 isNet] or remoteBlockheadInUseUniqueID@72 != 0 sets InteractionObject.needsToBeRemovedWhenInteractionEnds@96 = 1 and stops; else [currentBlockhead stopInteracting]. Then [self.world removeTileAtWorldX:pos.x worldY:pos.y createContentsFreeblockCount:1 createForegroundContentsFreeblockCount:0 removeBlockhead:arg] and [self setNeedsRemoved:1]..\n'),
    ),
    dict(
        name='ce_33',
        method='Chest -[removeFromMacroBlock]',
        types='v8@0:4',
        start=13360356,
        end=13361200,
        disasm='disasm_worldtileloader_ce_33.txt',
        base_add=13360372,
        base_literal=13361196,
        boundary='ARM.exidx end 0x00cbe030 (listing bound); next ObjC IMP 0x00cbe030 Chest -[staticGeometryDrawCubeCount]',
        selectors={
                 0xcbe008: (15236444, 'macroTiles'),
                 0xcbe018: (15236736, 'removeFromMacroBlock'),
                 0xcbe024: (15236732, 'removeSavedInventoryForChest:'),
        },
        imports={
                 0xcbe014: (17151900, 'objc_msgSendSuper2'),
                 0xcbe020: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcbdff8: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcbdffc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xcbe004: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xcbe028: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0xcbe01c: (15253232, 'OBJC_CLASS_$_Chest'),
        },
        instructions=[(13360356, 'push {r4, r5, r6, sl, fp, lr}'), (13361196, 'ldrshteq r1, [sl], -r8')],
        calls=[(13360464, 'bl loc.imp.objc_msgSend'), (13360508, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (13360672, 'bl loc.imp.objc_msgSend'), (13360716, 'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_'), (13360776, 'bl loc.imp.objc_msgSend'), (13360820, 'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_'), (13360936, 'bl loc.imp.objc_msgSend'), (13360980, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (13361092, 'blx lr'), (13361132, 'blx r2')],
        branches=[(13360544, 'beq', 13360584), (13360580, 'bne', 13360988), (13360856, 'bne', 13360984), (13360984, 'b', 13360988)],
        semantics=('[Chest -[removeFromMacroBlock]] (imp 0x00cbdce4, 211w): [read] -[removeFromMacroBlock] (0xcbdce4, 211w): reloads static geometry for its tile (world macroTiles + pos); if chestType 2/5 also reloadDrawBlockDynamicObjectItemQuadsForTile + DodoEggQuads (+ DynamicObjectQuads for type 5); then [self.dynamicWorld removeSavedInventoryForChest:self] followed by [super removeFromMacroBlock] via objc_msgSendSuper2 (class ref Chest at 0xcbe01c)..\n'),
    ),
    dict(
        name='ce_34',
        method='Chest -[removeItemIfAvailable:]',
        types='c12@0:4i8',
        start=13385280,
        end=13386172,
        disasm='disasm_worldtileloader_ce_34.txt',
        base_add=13385296,
        base_literal=13386168,
        boundary='ARM.exidx end 0x00cc41bc (listing bound); next ObjC IMP 0x00cc41bc Chest -[inventoryChanged]',
        selectors={
                 0xcc4198: (15236492, 'countByEnumeratingWithState:objects:count:'),
                 0xcc41a0: (15236636, 'loadInventoryItemsFromDiskIfNeeded'),
                 0xcc41a4: (15236476, 'count'),
                 0xcc41a8: (15236452, 'itemType'),
                 0xcc41ac: (15236488, 'objectAtIndex:'),
                 0xcc41b0: (15236660, 'contentsDidChange'),
                 0xcc41b4: (15236652, 'removeObjectAtIndex:'),
        },
        imports={
                 0xcc4194: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcc419c: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
        },
        classes={},
        instructions=[(13385280, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13386168, 'mlaseq sb, ip, ip, fp')],
        calls=[(13385440, 'blx r5'), (13385460, 'bl sym.imp.memset'), (13385524, 'blx lr'), (13385624, 'bl sym.imp.objc_enumerationMutation'), (13385696, 'blx r2'), (13385776, 'blx ip'), (13385792, 'blx r2'), (13385916, 'blx r5'), (13385944, 'blx r3'), (13385964, 'blx r2'), (13386084, 'blx ip')],
        branches=[(13385536, 'beq', 13386108), (13385616, 'beq', 13385628), (13385704, 'bls', 13385984), (13385812, 'bne', 13385980), (13385976, 'b', 13386120), (13385980, 'b', 13385984), (13385984, 'b', 13385988), (13386012, 'blo', 13385580), (13386104, 'bne', 13385580), (13386108, 'b', 13386112)],
        semantics=('[Chest -[removeItemIfAvailable:]] (imp 0x00cc3e40, 223w): [read] -[removeItemIfAvailable:] (0xcc3e40, 223w): [self loadInventoryItemsFromDiskIfNeeded]; fast-enumerate inventoryItems; per slot array with count>0: if [[slot objectAtIndex:0] itemType] == arg itemType -> [slot removeObjectAtIndex:[slot count]-1] (removes the LAST stack entry), [self contentsDidChange], return YES; if no slot matched -> return NO..\n'),
    ),
    dict(
        name='ce_35',
        method='Chest -[requiresHumanInteraction]',
        types='c8@0:4',
        start=13359336,
        end=13359364,
        disasm='disasm_worldtileloader_ce_35.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00cbd940; body trimmed at the next IMP 0x00cbd904 Chest -[chestType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13359336, 'sub sp, sp, 8'), (13359360, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Chest -[requiresHumanInteraction]] (imp 0x00cbd8e8, 7w): [read] -[requiresHumanInteraction] (0xcbd8e8, 7w): returns YES (sxtb of #1)..\n'),
    ),
    dict(
        name='ce_36',
        method='Chest -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=13358372,
        end=13358644,
        disasm='disasm_worldtileloader_ce_36.txt',
        base_add=13358388,
        base_literal=13358640,
        boundary='ARM.exidx end 0x00cbd634 (listing bound); next ObjC IMP 0x00cbd634 Chest -[destroyItemType]',
        selectors={
                 0xcbd618: (15236700, 'setNeedsRemoved:'),
                 0xcbd628: (15236692, 'stopInteracting'),
        },
        imports={
                 0xcbd614: (17151900, 'objc_msgSendSuper2'),
                 0xcbd624: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcbd620: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xcbd62c: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={
                 0xcbd61c: (15253232, 'OBJC_CLASS_$_Chest'),
        },
        instructions=[(13358372, 'push {r4, r5, fp, lr}'), (13358640, 'ldrhteq r2, [sl], -r8')],
        calls=[(13358488, 'blx lr'), (13358600, 'blx r2')],
        branches=[(13358500, 'beq', 13358604), (13358536, 'beq', 13358604)],
        semantics=('[Chest -[setNeedsRemoved:]] (imp 0x00cbd524, 68w): [read] -[setNeedsRemoved:] (0xcbd524, 68w): calls [super setNeedsRemoved:flag] (objc_msgSendSuper2); if flag and InteractionObject.isInUse@68 -> [[self currentBlockhead@56] stopInteracting] (0xcbd608)..\n'),
    ),
    dict(
        name='ce_37',
        method='Chest -[startInteractionWithBlockhead:]',
        types='v12@0:4@8',
        start=13361968,
        end=13362624,
        disasm='disasm_worldtileloader_ce_37.txt',
        base_add=13361984,
        base_literal=13362620,
        boundary='ARM.exidx end 0x00cbe5c0 (listing bound); next ObjC IMP 0x00cbe5c0 Chest -[addDrawCubeData:fromIndex:]',
        selectors={
                 0xcbe58c: (15236740, 'startInteractionWithBlockhead:'),
                 0xcbe59c: (15236576, 'activeBlockhead'),
                 0xcbe5ac: (15236580, 'addChestItemsToFoundList:'),
                 0xcbe5b4: (15236748, 'portalChestInventoryItems'),
                 0xcbe5b8: (15236744, 'portalChestManager'),
        },
        imports={
                 0xcbe588: (17151900, 'objc_msgSendSuper2'),
                 0xcbe598: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcbe594: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xcbe5a0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xcbe5a4: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcbe5a8: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcbe5b0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xcbe590: (15253232, 'OBJC_CLASS_$_Chest'),
        },
        instructions=[(13361968, 'push {r4, r5, r6, r7, fp, lr}'), (13362620, 'eorseq r1, sl, ip, lsr 15')],
        calls=[(13362060, 'blx lr'), (13362192, 'blx r2'), (13362364, 'blx r4'), (13362380, 'blx r2'), (13362412, 'blx r3'), (13362548, 'blx r3')],
        branches=[(13362100, 'beq', 13362560), (13362204, 'bne', 13362560), (13362240, 'bne', 13362420), (13362416, 'b', 13362556), (13362456, 'beq', 13362552), (13362552, 'b', 13362556), (13362556, 'b', 13362560)],
        semantics=('[Chest -[startInteractionWithBlockhead:]] (imp 0x00cbe330, 164w): [read] -[startInteractionWithBlockhead:] (0xcbe330, 164w): [super startInteractionWithBlockhead:bh] (objc_msgSendSuper2); returns unless currentBlockhead@56 != nil AND [self.dynamicWorld activeBlockhead] == currentBlockhead. Then chestType==4 -> [self.world addChestItemsToFoundList:[[self.world portalChestManager] portalChestInventoryItems]] (0xcbe4ec); else if inventoryItems@100 != nil -> [self.world addChestItemsToFoundList:inventoryItems] (0xcbe574)..\n'),
    ),
    dict(
        name='ce_38',
        method='Chest -[staticGeometryDodoEggCount]',
        types='i8@0:4',
        start=13381952,
        end=13382704,
        disasm='disasm_worldtileloader_ce_38.txt',
        base_add=13381968,
        base_literal=13382700,
        boundary='ARM.exidx end 0x00cc3430 (listing bound); next ObjC IMP 0x00cc3430 Chest -[addDodoEggDrawQuadData:fromIndex:]',
        selectors={
                 0xcc3418: (15236476, 'count'),
                 0xcc341c: (15236488, 'objectAtIndex:'),
                 0xcc3420: (15236596, 'dataB'),
                 0xcc3424: (15236452, 'itemType'),
                 0xcc3428: (15236592, 'lastObject'),
        },
        imports={
                 0xcc3414: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcc3400: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcc3404: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcc3408: (17167588, 'OBJC_IVAR_$_Chest.shelfRenderItems', 116),
                 0xcc3410: (17167592, 'OBJC_IVAR_$_Chest.shelfItemDataBs', 132),
        },
        classes={},
        instructions=[(13381952, 'push {r4, r5, fp, lr}'), (13382700, 'mlaseq sb, ip, sb, ip')],
        calls=[(13382328, 'blx ip'), (13382352, 'blx r2'), (13382460, 'blx r4'), (13382484, 'blx r2'), (13382508, 'blx r2')],
        branches=[(13382020, 'beq', 13382060), (13382056, 'bne', 13382644), (13382088, 'bge', 13382636), (13382112, 'bge', 13382616), (13382236, 'beq', 13382520), (13382360, 'bne', 13382380), (13382376, 'b', 13382600), (13382516, 'b', 13382552), (13382528, 'bne', 13382548), (13382544, 'b', 13382600), (13382548, 'b', 13382552), (13382560, 'bne', 13382588), (13382572, 'beq', 13382588), (13382612, 'b', 13382104), (13382616, 'b', 13382620), (13382632, 'b', 13382080)],
        semantics=('[Chest -[staticGeometryDodoEggCount]] (imp 0x00cc3140, 188w): [read] -[staticGeometryDodoEggCount] (0xcc3140, 188w): 0 unless chestType 2/5. 2x2 shelf loop (slot=row*2+col, 0..3): itemType/dataB = cached shelfRenderItems[slot]/shelfItemDataBs[slot], replaced by [arr lastObject] itemType/dataB when inventoryItems[slot] is non-empty (empty slot with cached itemType==0 skips). Counts slots where itemType==0x5b AND dataB!=0 (dodo eggs). Returns the count..\n'),
    ),
    dict(
        name='ce_39',
        method='Chest -[staticGeometryDrawCubeCount]',
        types='i8@0:4',
        start=13361200,
        end=13361968,
        disasm='disasm_worldtileloader_ce_39.txt',
        base_add=13361216,
        base_literal=13361964,
        boundary='ARM.exidx end 0x00cbe330 (listing bound); next ObjC IMP 0x00cbe330 Chest -[startInteractionWithBlockhead:]',
        selectors={
                 0xcbe31c: (15236476, 'count'),
                 0xcbe320: (15236488, 'objectAtIndex:'),
                 0xcbe324: (15236452, 'itemType'),
                 0xcbe328: (15236592, 'lastObject'),
        },
        imports={
                 0xcbe318: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcbe308: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcbe30c: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcbe310: (17167588, 'OBJC_IVAR_$_Chest.shelfRenderItems', 116),
        },
        classes={},
        instructions=[(13361200, 'push {r4, r5, fp, lr}'), (13361964, 'eorseq r1, sl, ip, lsr 21')],
        calls=[(13361544, 'blx ip'), (13361568, 'blx r2'), (13361656, 'blx ip'), (13361680, 'blx r2'), (13361728, 'bl sym.itemTypeIsBlock_ItemType_')],
        branches=[(13361268, 'beq', 13361308), (13361304, 'bne', 13361868), (13361336, 'bge', 13361804), (13361360, 'bge', 13361784), (13361452, 'beq', 13361692), (13361576, 'bne', 13361596), (13361592, 'b', 13361768), (13361688, 'b', 13361724), (13361700, 'bne', 13361720), (13361716, 'b', 13361768), (13361720, 'b', 13361724), (13361740, 'beq', 13361756), (13361780, 'b', 13361352), (13361784, 'b', 13361788), (13361800, 'b', 13361328), (13361848, 'bne', 13361864), (13361864, 'b', 13361868), (13361900, 'beq', 13361916)],
        semantics=('[Chest -[staticGeometryDrawCubeCount]] (imp 0x00cbe030, 192w): [read] -[staticGeometryDrawCubeCount] (0xcbe030, 192w): 2x2 shelf loop with the same cache/inventory resolution as ce_38; counts slots whose itemType passes itemTypeIsBlock. Result: chestType==2 -> blockCount + 2; chestType==5 -> blockCount + 2 + 3 + 1 = blockCount+6; other types -> 1 (no loop)..\n'),
    ),
    dict(
        name='ce_40',
        method='Chest -[staticGeometryDrawItemQuadCount]',
        types='i8@0:4',
        start=13377144,
        end=13377924,
        disasm='disasm_worldtileloader_ce_40.txt',
        base_add=13377160,
        base_literal=13377920,
        boundary='ARM.exidx end 0x00cc2184 (listing bound); next ObjC IMP 0x00cc21d4 Chest -[addDrawItemQuadData:fromIndex:]',
        selectors={
                 0xcc216c: (15236476, 'count'),
                 0xcc2170: (15236488, 'objectAtIndex:'),
                 0xcc2174: (15236596, 'dataB'),
                 0xcc2178: (15236452, 'itemType'),
                 0xcc217c: (15236592, 'lastObject'),
        },
        imports={
                 0xcc2168: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcc2154: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcc2158: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcc215c: (17167588, 'OBJC_IVAR_$_Chest.shelfRenderItems', 116),
                 0xcc2164: (17167592, 'OBJC_IVAR_$_Chest.shelfItemDataBs', 132),
        },
        classes={},
        instructions=[(13377144, 'push {r4, r5, fp, lr}'), (13377920, 'eorseq sp, sb, r4, ror 24')],
        calls=[(13377520, 'blx ip'), (13377544, 'blx r2'), (13377652, 'blx r4'), (13377676, 'blx r2'), (13377700, 'blx r2'), (13377748, 'bl sym.itemTypeIsBlock_ItemType_'), (13377792, 'bl 0xcc2184')],
        branches=[(13377212, 'beq', 13377252), (13377248, 'bne', 13377864), (13377280, 'bge', 13377856), (13377304, 'bge', 13377836), (13377428, 'beq', 13377712), (13377552, 'bne', 13377572), (13377568, 'b', 13377820), (13377708, 'b', 13377744), (13377720, 'bne', 13377740), (13377736, 'b', 13377820), (13377740, 'b', 13377744), (13377760, 'bne', 13377808), (13377772, 'bne', 13377788), (13377784, 'bne', 13377808), (13377832, 'b', 13377296), (13377836, 'b', 13377840), (13377852, 'b', 13377272)],
        semantics=('[Chest -[staticGeometryDrawItemQuadCount]] (imp 0x00cc1e78, 195w): [read] -[staticGeometryDrawItemQuadCount] (0xcc1e78, 195w): same 2x2 cache/inventory resolution; for each slot skips blocks and (itemType==0x5b && dataB!=0), then accumulates helper 0xcc2184(itemType) = 2 when itemType==103 or itemTypeCanBeColored(itemType) (C++ _Z20itemTypeCanBeColored8ItemType), else 1. Returns 0 unless chestType 2/5..\n'),
    ),
    dict(
        name='ce_41',
        method='Chest -[staticGeometryDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=13375996,
        end=13376100,
        disasm='disasm_worldtileloader_ce_41.txt',
        base_add=13376008,
        base_literal=13376096,
        boundary='ARM.exidx end 0x00cc1a64 (listing bound); next ObjC IMP 0x00cc1a64 Chest -[addDrawQuadData:fromIndex:forMacroPos:]',
        selectors={},
        imports={},
        ivars={
                 0xcc1a5c: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
        },
        classes={},
        instructions=[(13375996, 'push {fp, lr}'), (13376096, 'eorseq lr, sb, r4, ror 1')],
        calls=[],
        branches=[(13376056, 'bne', 13376072), (13376068, 'b', 13376080)],
        semantics=('[Chest -[staticGeometryDrawQuadCountForMacroPos:]] (imp 0x00cc19fc, 26w): [read] -[staticGeometryDrawQuadCountForMacroPos:] (0xcc19fc, 26w): returns 1 when chestType==5, else 0..\n'),
    ),
    dict(
        name='ce_42',
        method='Chest -[title]',
        types='@8@0:4',
        start=13358716,
        end=13359156,
        disasm='disasm_worldtileloader_ce_42.txt',
        base_add=13358724,
        base_literal=13359152,
        boundary='ARM.exidx end 0x00cbd834 (listing bound); next ObjC IMP 0x00cbd834 Chest -[actionTitle]',
        selectors={},
        imports={
                 0xcbd814: (16397272, '__CFConstantStringClassReference'),
                 0xcbd818: (16397256, '__CFConstantStringClassReference'),
                 0xcbd81c: (16397240, '__CFConstantStringClassReference'),
                 0xcbd820: (16397224, '__CFConstantStringClassReference'),
                 0xcbd824: (16397208, '__CFConstantStringClassReference'),
                 0xcbd828: (16397192, '__CFConstantStringClassReference'),
                 0xcbd82c: (16397176, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xcbd810: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
        },
        classes={},
        instructions=[(13358716, 'sub sp, sp, 0x10'), (13359152, 'eorseq r2, sl, r8, ror 8')],
        calls=[],
        branches=[(13358768, 'bne', 13358792), (13358788, 'b', 13359108), (13358824, 'bne', 13358848), (13358844, 'b', 13359108), (13358880, 'bne', 13358904), (13358900, 'b', 13359108), (13358936, 'bne', 13358960), (13358956, 'b', 13359108), (13358992, 'bne', 13359016), (13359012, 'b', 13359108), (13359048, 'bne', 13359072), (13359068, 'b', 13359108), (13359072, 'b', 13359076), (13359076, 'b', 13359080), (13359080, 'b', 13359084), (13359084, 'b', 13359088), (13359088, 'b', 13359092)],
        semantics=('[Chest -[title]] (imp 0x00cbd67c, 110w): [read] -[title] (0xcbd67c, 110w): chestType dispatch to CFString constants: 1->\'SAFE\', 2->\'SHELF\', 3->\'GOLDEN CHEST\', 4->\'PORTAL CHEST\', 5->\'CABINET\', 6->\'FEEDER CHEST\', default->\'CHEST\' (cells 0xcbd82c/828/824/820/81c/818/814)..\n'),
    ),
    dict(
        name='ce_43',
        method='Chest -[updateInventoryWithData:]',
        types='v12@0:4@8',
        start=13336896,
        end=13338804,
        disasm='disasm_worldtileloader_ce_43.txt',
        base_add=13336912,
        base_literal=13338800,
        boundary='ARM.exidx end 0x00cb88b4 (listing bound); next ObjC IMP 0x00cb88b4 Chest -[remoteInventoryDataRecieved:]',
        selectors={
                 0xcb8868: (15236464, 'initWithCapacity:'),
                 0xcb886c: (15236460, 'alloc'),
                 0xcb8874: (15236472, 'release'),
                 0xcb8878: (15236556, 'gzipInflate'),
                 0xcb8880: (15236576, 'activeBlockhead'),
                 0xcb8888: (15236580, 'addChestItemsToFoundList:'),
                 0xcb8890: (15236484, 'addObject:'),
                 0xcb8894: (15236480, 'array'),
                 0xcb8898: (15236492, 'countByEnumeratingWithState:objects:count:'),
                 0xcb889c: (15236488, 'objectAtIndex:'),
                 0xcb88a0: (15236452, 'itemType'),
                 0xcb88a4: (15236500, 'autorelease'),
                 0xcb88a8: (15236496, 'initWithSaveData:'),
        },
        imports={
                 0xcb8864: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcb885c: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcb8860: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcb887c: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xcb8884: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xcb888c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xcb8870: (15250968, 'OBJC_CLASS_$_NSMutableArray'),
                 0xcb88ac: (15250972, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(13336896, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13338800, 'mlaseq sl, ip, sb, r7')],
        calls=[(13337076, 'blx r2'), (13337128, 'blx r3'), (13337160, 'bl 0xcb623c'), (13337240, 'blx lr'), (13337328, 'blx r2'), (13337332, 'bl 0xcb7aa4'), (13337404, 'bl 0xcb623c'), (13337592, 'blx r2'), (13337636, 'blx ip'), (13337660, 'blx r3'), (13337684, 'bl sym.imp.memset'), (13337732, 'blx lr'), (13337832, 'bl sym.imp.objc_enumerationMutation'), (13337960, 'blx ip'), (13337980, 'blx r3'), (13337996, 'blx r2'), (13338020, 'blx r2'), (13338080, 'blx r3'), (13338184, 'blx ip'), (13338368, 'blx r2'), (13338472, 'blx r3'), (13338544, 'bl 0xcb623c'), (13338640, 'blx lr'), (13338684, 'blx ip')],
        branches=[(13336960, 'bne', 13336968), (13336964, 'b', 13338708), (13337284, 'beq', 13338484), (13337352, 'beq', 13338480), (13337416, 'bge', 13338232), (13337744, 'beq', 13338208), (13337824, 'beq', 13337836), (13338028, 'beq', 13338084), (13338084, 'b', 13338088), (13338112, 'blo', 13337788), (13338204, 'bne', 13337788), (13338208, 'b', 13338212), (13338212, 'b', 13338216), (13338228, 'b', 13337368), (13338276, 'beq', 13338476), (13338380, 'bne', 13338476), (13338476, 'b', 13338480), (13338480, 'b', 13338484), (13338492, 'bne', 13338708), (13338556, 'bge', 13338704), (13338700, 'b', 13338508), (13338704, 'b', 13338708)],
        semantics=('[Chest -[updateInventoryWithData:]] (imp 0x00cb8140, 477w): [census-lite] -[updateInventoryWithData:] (0xcb8140, 477w): returns for chestType==4. Releases inventoryItems@100 and replaces it with [[NSMutableArray alloc] initWithCapacity:0xcb623c(chestType)] (4 slots for types 2/5, else 16). If data != nil: arr = plist-decode (gzipInflate -> 0xcb7aa4/0xcc5494); if arr != nil loop i in 0..<slotCount: sub=[NSMutableArray array] appended to inventoryItems; slotData=[arr objectAtIndex:i]; inner loop: item=[[InventoryItem alloc] initWithSaveData:d] + autorelease, appended to sub unless [item itemType]==0xb; then sets a \'loaded\' flag [fp-0x29]=1. If currentBlockhead@56 != nil and == [dynamicWorld activeBlockhead] -> [self.world addChestItemsToFoundList:inventoryItems] (0xcb8768). When the flag is 0 (nil data / nil plist), pads inventoryItems with empty [NSMutableArray array] entries up to slotCount (0xcb884c)..\n'),
    ),
    dict(
        name='ce_44',
        method='Chest -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=13338888,
        end=13341932,
        disasm='disasm_worldtileloader_ce_44.txt',
        base_add=13338904,
        base_literal=13341928,
        boundary='ARM.exidx end 0x00cb94ec (listing bound); next ObjC IMP 0x00cb94ec Chest -[dealloc]',
        selectors={
                 0xcb9454: (15236588, 'interactionObjectCreationNetData'),
                 0xcb9474: (15236608, 'dictionary'),
                 0xcb947c: (15236604, 'dataWithBytes:length:'),
                 0xcb9488: (15236612, 'setObject:forKey:'),
                 0xcb949c: (15236492, 'countByEnumeratingWithState:objects:count:'),
                 0xcb94a0: (15236480, 'array'),
                 0xcb94a8: (15236484, 'addObject:'),
                 0xcb94ac: (15236452, 'itemType'),
                 0xcb94b0: (15236568, 'saveData'),
                 0xcb94b8: (15236616, 'appendData:'),
                 0xcb94bc: (15236572, 'gzipDeflate'),
                 0xcb94c0: (15236476, 'count'),
                 0xcb94c4: (15236488, 'objectAtIndex:'),
                 0xcb94c8: (15236592, 'lastObject'),
                 0xcb94d0: (15236596, 'dataB'),
                 0xcb94d4: (15236600, 'dynamicObjectSaveDict'),
                 0xcb94dc: (15236468, 'objectForKey:'),
                 0xcb94e4: (15236524, 'intValue'),
        },
        imports={
                 0xcb9470: (17151904, 'objc_msgSend'),
                 0xcb9484: (16397096, '__CFConstantStringClassReference'),
                 0xcb9490: (16397112, '__CFConstantStringClassReference'),
                 0xcb94b4: (16397016, '__CFConstantStringClassReference'),
                 0xcb94e0: (16397128, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xcb9458: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcb945c: (17167584, 'OBJC_IVAR_$_Chest.inventoryItems', 100),
                 0xcb9460: (17167588, 'OBJC_IVAR_$_Chest.shelfRenderItems', 116),
                 0xcb9468: (17167592, 'OBJC_IVAR_$_Chest.shelfItemDataBs', 132),
                 0xcb946c: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xcb948c: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0xcb9494: (17167596, 'OBJC_IVAR_$_Chest.inventoryNeedsToBeSentWithUpdate', 112),
                 0xcb9498: (17156832, 'OBJC_IVAR_$_InteractionObject.proxyObjectOwner', 92),
        },
        classes={
                 0xcb9478: (15250984, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0xcb9480: (15250980, 'OBJC_CLASS_$_NSMutableData'),
                 0xcb94a4: (15250968, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(13338888, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13341928, 'ldrsbteq r7, [sl], -r4')],
        calls=[(13338980, 'bl loc.imp.objc_msgSend_stret'), (13339016, 'bl sym.imp.memset'), (13339056, 'bl sym.imp.memcpy'), (13339324, 'blx ip'), (13339348, 'blx r2'), (13339472, 'bl loc.imp.objc_msgSend'), (13339492, 'bl loc.imp.objc_msgSend'), (13339532, 'bl loc.imp.objc_msgSend'), (13339572, 'blx r3'), (13339576, 'bl sym.itemTypeIsWorkbench_ItemType_'), (13339632, 'bl loc.imp.objc_msgSend'), (13339656, 'bl loc.imp.objc_msgSend'), (13339672, 'bl loc.imp.objc_msgSend'), (13340020, 'blx r5'), (13340056, 'blx r3'), (13340180, 'blx ip'), (13340308, 'blx ip'), (13340580, 'blx r2'), (13340604, 'bl sym.imp.memset'), (13340668, 'blx lr'), (13340768, 'bl sym.imp.objc_enumerationMutation'), (13340920, 'blx r2'), (13340960, 'blx r3'), (13340980, 'bl sym.imp.memset'), (13341028, 'blx lr'), (13341128, 'bl sym.imp.objc_enumerationMutation'), (13341200, 'blx r2'), (13341280, 'blx ip'), (13341312, 'blx r3'), (13341416, 'blx ip'), (13341544, 'blx ip'), (13341644, 'blx ip'), (13341676, 'bl 0xcb7fd4'), (13341736, 'blx lr'), (13341764, 'blx r3')],
        branches=[(13338964, 'beq', 13338988), (13338984, 'b', 13339020), (13339104, 'beq', 13339144), (13339140, 'bne', 13339900), (13339180, 'beq', 13339752), (13339208, 'bge', 13339748), (13339232, 'bge', 13339728), (13339356, 'bne', 13339408), (13339404, 'b', 13339712), (13339588, 'beq', 13339700), (13339724, 'b', 13339224), (13339728, 'b', 13339732), (13339744, 'b', 13339200), (13339748, 'b', 13339896), (13339772, 'bge', 13339892), (13339888, 'b', 13339764), (13339892, 'b', 13339896), (13339896, 'b', 13339900), (13340092, 'beq', 13340184), (13340220, 'beq', 13340312), (13340344, 'beq', 13341672), (13340384, 'beq', 13341672), (13340420, 'bne', 13340464), (13340460, 'beq', 13341672), (13340680, 'beq', 13341568), (13340760, 'beq', 13340772), (13341040, 'beq', 13341440), (13341120, 'beq', 13341132), (13341208, 'beq', 13341316), (13341316, 'b', 13341320), (13341344, 'blo', 13341084), (13341436, 'bne', 13341084), (13341440, 'b', 13341444), (13341444, 'b', 13341448), (13341472, 'blo', 13340724), (13341564, 'bne', 13340724), (13341568, 'b', 13341572)],
        semantics=('[Chest -[updateNetDataForClient:]] (imp 0x00cb8908, 761w): [census-lite] -[updateNetDataForClient:] (0xcb8908, 761w): builds the net payload. (1) hdr = 0x40 bytes, first 0x28 copied from [self interactionObjectCreationNetData] (objc_msgSend_stret; memset 0 when self nil). (1b) hdr[0x38] = self.chestType (byte store at 0xcb89c8, fp-0x30 == fp-0x68+0x38). (2) chestType 2/5: fills hdr+0x28 (4x u16 = shelfRenderItems) and hdr+0x30 (4x u16 = shelfItemDataBs) in a 2x2 loop: empty slot -> 0, else [slotArr lastObject] itemType + dataB, and when itemTypeIsWorkbench the level ([[[lastObject] dynamicObjectSaveDict] objectForKey:@"level"] intValue]); when inventoryItems==nil it copies the cached shelfRenderItems/shelfItemDataBs[0..3] ivars into the header. (3) data=[NSMutableData dataWithBytes:&hdr length:0x40]; dict=[NSMutableDictionary dictionary]; dict[@"ownerID"]=ownerID (if non-nil), dict[@"ownerName"]=ownerName (if non-nil). (4) when chestType!=4 && inventoryItems!=nil && (inventoryNeedsToBeSentWithUpdate@112 || proxyObjectOwner@92): nested fast-enum over inventoryItems builds entries[slot]=[item saveData...] skipping itemType 0xb, dict[@"saveItemSlots"]=entries, and the flag inventoryNeedsToBeSentWithUpdate@112 is cleared (0xcb93e4 strb 0). (5) append plist bytes: [data appendData:[(0xcb7fd4 binary plist of dict) gzipDeflate]]; returns data (0x944c)..\n'),
    ),
    dict(
        name='ce_45',
        method='Chest -[updatePosition:]',
        types='v16@0:4{?=ii}8',
        start=13360016,
        end=13360356,
        disasm='disasm_worldtileloader_ce_45.txt',
        base_add=13360032,
        base_literal=13360352,
        boundary='ARM.exidx end 0x00cbdce4 (listing bound); next ObjC IMP 0x00cbdce4 Chest -[removeFromMacroBlock]',
        selectors={
                 0xcbdccc: (15236692, 'stopInteracting'),
                 0xcbdcdc: (15236728, 'updatePosition:'),
        },
        imports={
                 0xcbdcc8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcbdcc0: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xcbdcc4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xcbdcd0: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={
                 0xcbdcd4: (15253232, 'OBJC_CLASS_$_Chest'),
        },
        instructions=[(13360016, 'push {fp, lr}'), (13360352, 'eorseq r1, sl, ip, asr 30')],
        calls=[(13360228, 'blx r2'), (13360308, 'bl loc.imp.objc_msgSendSuper2')],
        branches=[(13360084, 'beq', 13360232), (13360124, 'bne', 13360168), (13360164, 'beq', 13360232)],
        semantics=('[Chest -[updatePosition:]] (imp 0x00cbdb90, 85w): [read] -[updatePosition:] (0xcbdb90, 85w): if InteractionObject.isInUse@68 and the new (x,y) differs from DynamicObject.pos@16 -> [[self currentBlockhead@56] stopInteracting] (0xcbdc64); then [super updatePosition:] via objc_msgSendSuper2 (class ref Chest, 0xcbdcb4)..\n'),
    ),
    dict(
        name='ce_46',
        method='Chest -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=13354756,
        end=13357232,
        disasm='disasm_worldtileloader_ce_46.txt',
        base_add=13354772,
        base_literal=13357228,
        boundary='ARM.exidx end 0x00cbd0b0 (listing bound); next ObjC IMP 0x00cbd0ec Chest -[worldContentsChanged:]',
        selectors={
                 0xcbd084: (15236680, 'worldWidthMacro'),
                 0xcbd0a8: (15236676, 'remove:'),
        },
        imports={
                 0xcbd0a4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xcbd070: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xcbd074: (17167580, 'OBJC_IVAR_$_Chest.chestType', 108),
                 0xcbd078: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xcbd080: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(13354756, 'push {r4, r5, fp, lr}'), (13357228, 'ldrsbteq r3, [sl], -r8')],
        calls=[(13355284, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13355352, 'blx r3'), (13355452, 'bl loc.imp.objc_msgSend'), (13355476, 'bl sym.imp.__aeabi_idiv'), (13355572, 'bl loc.imp.objc_msgSend'), (13355692, 'bl loc.imp.objc_msgSend'), (13355708, 'bl sym.imp.__aeabi_idiv'), (13355804, 'bl loc.imp.objc_msgSend'), (13355888, 'bl 0xcbd0b0'), (13356060, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13356088, 'bl sym.tileIsSolid_Tile_'), (13356192, 'bl sym.makeIntpair_int__int_'), (13356212, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (13356316, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13356440, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13356504, 'bl sym.makeIntpair_int__int_'), (13356524, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (13356560, 'bl sym.tileIsSolid_Tile_'), (13356660, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13356724, 'bl sym.makeIntpair_int__int_'), (13356744, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (13356780, 'bl sym.tileIsSolid_Tile_'), (13356880, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13356944, 'bl sym.makeIntpair_int__int_'), (13356964, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (13357000, 'bl sym.tileIsSolid_Tile_'), (13357060, 'blx r3')],
        branches=[(13354820, 'beq', 13354828), (13354824, 'b', 13357160), (13355064, 'beq', 13357160), (13355132, 'beq', 13355172), (13355168, 'bne', 13355364), (13355208, 'bne', 13355360), (13355304, 'bne', 13355356), (13355356, 'b', 13355360), (13355360, 'b', 13357096), (13355488, 'blt', 13355604), (13355600, 'b', 13355884), (13355720, 'bge', 13355836), (13355832, 'b', 13355876), (13355896, 'bge', 13357092), (13355940, 'beq', 13355984), (13355980, 'blt', 13357092), (13356080, 'beq', 13357088), (13356100, 'bne', 13357088), (13356224, 'bne', 13357084), (13356240, 'beq', 13357084), (13356336, 'beq', 13357080), (13356352, 'bne', 13357080), (13356536, 'bne', 13357076), (13356552, 'beq', 13357076), (13356572, 'bne', 13357076), (13356756, 'bne', 13357072), (13356772, 'beq', 13357072), (13356792, 'bne', 13357072), (13356976, 'bne', 13357068), (13356992, 'beq', 13357068), (13357012, 'bne', 13357068), (13357064, 'b', 13357160), (13357068, 'b', 13357072), (13357072, 'b', 13357076), (13357076, 'b', 13357080), (13357080, 'b', 13357084), (13357084, 'b', 13357088), (13357088, 'b', 13357092), (13357092, 'b', 13357096), (13357096, 'b', 13357100), (13357156, 'b', 13354912)],
        semantics=('[Chest -[worldChanged:]] (imp 0x00cbc704, 619w): [census-lite] -[worldChanged:] (0xcbc704, 619w): returns immediately when DynamicObject.isNet@52, and also when the arg\'s pair compares equal (compare at 0xcbc824; the arg is a 16-byte struct of two intpairs - the body iterates it twice via pointer += 8 and loops back to 0xcbc7a0). Thread A (chestType 2/5, 0xcbc878): when arg.x == self.pos.x, tile = tileAtWorldPositionLoaded(pos.x,pos.y,world); if tile byte[1]==2 -> [self remove:0] (0xcbc958). Thread B (all other chest types, 0xcbc964): wrap-aware horizontal check - delta = pos.x - arg.x; half = [world worldWidthMacro]*32/2; only |delta| within {half, half via +width*32} (helper 0xcbd0b0 tests the residual, abs>=2 -> return) and arg.y in {pos.y-1} or >= pos.y proceed; then a chain of neighbor probes with makeIntpair + tileIsHalfDepth + tileIsSolid + byte[3]==0x60 gates: tile(pos.x,pos.y-1) (non-null, non-solid, non-halfDepth, !=0x60), tile(pos.x,pos.y) (byte[1]==2), then tile(pos.x-1,pos.y), tile(pos.x+1,pos.y), tile(pos.x,pos.y+1) each gated on halfDepth/0x60/solid; if the whole chain passes -> [self remove:0] (0xcbd004). Calls: tileAtWorldPositionLoaded x6, tileIsSolid x4, makeIntpair x4, tileIsHalfDepth x4; the helper 0xcbd0b0 at the boundary is a small int fixup (call row 0xcbd0b0)..\n'),
    ),
    dict(
        name='ce_47',
        method='Chest -[worldContentsChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=13357292,
        end=13357376,
        disasm='disasm_worldtileloader_ce_47.txt',
        base_add=13357308,
        base_literal=13357372,
        boundary='ARM.exidx end 0x00cbd188; body trimmed at the next IMP 0x00cbd140 Chest -[freeblockCreationItemType]',
        selectors={
                 0xcbd138: (15236684, 'worldChanged:'),
        },
        imports={
                 0xcbd134: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(13357292, 'push {fp, lr}'), (13357372, 'ldrshteq r2, [sl], -r0')],
        calls=[(13357352, 'blx ip')],
        branches=[],
        semantics=('[Chest -[worldContentsChanged:]] (imp 0x00cbd0ec, 21w): [read] -[worldContentsChanged:] (0xcbd0ec, 21w): tail-calls [self worldChanged:arg] (sel cell 0xcbd138)..\n'),
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
        'batch': 'Chest (E139): the container dynamic object; 48 bodies',
        'claim': ('the chest container object (inventory storage, net/save round-trip, geometry)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'chest.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale chest.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
