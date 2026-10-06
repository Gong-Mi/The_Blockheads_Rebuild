#!/usr/bin/env python3
"""Hash-gated recovery of the TradePortal economics batch (E9b).

Part 2 of 2 of the trade portal (DynamicObject 0x32): the trade economics -
14 bodies, 3573 instruction words, from the pinned original libApplication.so
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
    'bl 0xd37798': 0x00d37798,
    'bl 0xd3b1f4': 0x00d3b1f4,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_powf': 0x001c3f98,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.itemTypeIsSowable_ItemType_': 0x0056871c,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsHalfDepth_Tile__World__intpair_': 0x00a14450,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
}

SPECS = [
    dict(
        name='tp_loadprice',
        method='TradePortal -[loadPriceOffsets:]',
        types='v12@0:4@8',
        start=13859448,
        end=13860236,
        disasm='disasm_tradeportal_loadpriceoffsets_closure.txt',
        base_add=13859464,
        base_literal=13860232,
        boundary='ARM.exidx end 0x00d37d8c; the next ObjC IMP ([worldChanged:]) is at 0x00d3a8f8, so the body is bounded by the exidx entry',
        selectors={
                 0xd37d6c: (15239152, 'countByEnumeratingWithState:objects:count:'),
                 0xd37d70: (15239160, 'doubleValue'),
                 0xd37d74: (15239156, 'objectForKey:'),
                 0xd37d78: (15239168, 'setObject:forKey:'),
                 0xd37d7c: (15239164, 'numberWithDouble:'),
        },
        imports={
                 0xd37d68: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd37d84: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128),
        },
        classes={
                 0xd37d80: (15251284, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(13859448, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13859704, 'vmov.f64 d0, 5'), (13859552, 'bl sym.imp.memset'), (13860232, 'eorseq r8, r2, r4, rrx')],
        calls=[(13859552, 'bl sym.imp.memset'), (13859600, 'blx lr'), (13859700, 'bl sym.imp.objc_enumerationMutation'), (13859808, 'blx ip'), (13859832, 'blx r2'), (13860028, 'blx ip'), (13860064, 'blx ip'), (13860164, 'blx ip')],
        branches=[(13859612, 'beq', 13860188), (13859692, 'beq', 13859704), (13859860, 'bpl', 13859876), (13859872, 'b', 13859924), (13859900, 'ble', 13859920), (13859920, 'b', 13859924), (13860092, 'blo', 13859656), (13860184, 'bne', 13859656), (13860188, 'b', 13860192)],
        semantics=("loadPriceOffsets: rebuilds the portal's price-offset dictionary by fast-enumerating the source dict (memset of the 0x20-byte NSFastEnumeration state, countByEnumeratingWithState:objects:count: at 0xd37ae0): per key objectForKey: then doubleValue, clamped to [0.5, 2.0] by the two VFP compare branches (0.5 at 0xd37b78, 2.0 at 0xd37c28/0xd37c44), then [NSNumber numberWithDouble:] and [self.localPriceOffsets setObject:forKey:] (ivar@128); the enumeration guard calls objc_enumerationMutation at 0xd37b74. Same clamp bounds as the b4i C++ contract in reconstruction/recovered/trade_portal_price_offsets.cpp."),
    ),
    dict(
        name='tp_worldchanged',
        method='TradePortal -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=13871352,
        end=13873652,
        disasm='disasm_tradeportal_worldchanged.txt',
        base_add=13871368,
        base_literal=13873648,
        boundary='ARM.exidx end 0x00d3b1f4; the next ObjC IMP ([worldContentsChanged:]) is at 0x00d3b230, past a 0x3c-byte non-method gap',
        selectors={
                 0xd3b1b8: (15239308, 'worldChanged:'),
                 0xd3b1cc: (15239312, 'worldWidthMacro'),
                 0xd3b1ec: (15239316, 'remove:'),
        },
        imports={
                 0xd3b1b4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd3b1b0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xd3b1bc: (17168468, 'OBJC_IVAR_$_TradePortal.light', 100),
                 0xd3b1c0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd3b1c8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(13871352, 'push {r4, sl, fp, lr}'), (13871416, 'beq 0xd3a940'), (13871512, 'blx ip'), (13872308, 'bl 0xd3b1f4'), (13872480, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13873480, 'blx r3'), (13873648, 'eorseq r5, r2, r4, ror 3')],
        calls=[(13871512, 'blx ip'), (13871872, 'bl loc.imp.objc_msgSend'), (13871896, 'bl sym.imp.__aeabi_idiv'), (13871992, 'bl loc.imp.objc_msgSend'), (13872112, 'bl loc.imp.objc_msgSend'), (13872128, 'bl sym.imp.__aeabi_idiv'), (13872224, 'bl loc.imp.objc_msgSend'), (13872308, 'bl 0xd3b1f4'), (13872480, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13872508, 'bl sym.tileIsSolid_Tile_'), (13872612, 'bl sym.makeIntpair_int__int_'), (13872632, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (13872736, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13872860, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13872924, 'bl sym.makeIntpair_int__int_'), (13872944, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (13872980, 'bl sym.tileIsSolid_Tile_'), (13873080, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13873144, 'bl sym.makeIntpair_int__int_'), (13873164, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (13873200, 'bl sym.tileIsSolid_Tile_'), (13873300, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13873364, 'bl sym.makeIntpair_int__int_'), (13873384, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (13873420, 'bl sym.tileIsSolid_Tile_'), (13873480, 'blx r3')],
        branches=[(13871416, 'beq', 13871424), (13871420, 'b', 13873576), (13871752, 'beq', 13873576), (13871908, 'blt', 13872024), (13872020, 'b', 13872304), (13872140, 'bge', 13872256), (13872252, 'b', 13872296), (13872316, 'bge', 13873512), (13872360, 'beq', 13872404), (13872400, 'blt', 13873512), (13872500, 'beq', 13873508), (13872520, 'bne', 13873508), (13872644, 'bne', 13873504), (13872660, 'beq', 13873504), (13872756, 'beq', 13873500), (13872772, 'bne', 13873500), (13872956, 'bne', 13873496), (13872972, 'beq', 13873496), (13872992, 'bne', 13873496), (13873176, 'bne', 13873492), (13873192, 'beq', 13873492), (13873212, 'bne', 13873492), (13873396, 'bne', 13873488), (13873412, 'beq', 13873488), (13873432, 'bne', 13873488), (13873484, 'b', 13873576), (13873488, 'b', 13873492), (13873492, 'b', 13873496), (13873496, 'b', 13873500), (13873500, 'b', 13873504), (13873504, 'b', 13873508), (13873508, 'b', 13873512), (13873512, 'b', 13873516), (13873572, 'b', 13871600)],
        semantics=('worldChanged:(std::vector<intpair>&): the argument is the changed-position vector (begin/end at *(v+0)/*(v+4), 8-byte intpair elements; no stret). Gate: self.isNet@52 != 0 -> return (0xd3a938, 0xd3a93c). Otherwise the single delegate message is [self.light@100 worldChanged:changed] with plain objc_msgSend at 0xd3a998 - the receiver is the light ivar, not super (no objc_msgSendSuper import in this body). Then per element (cp): dx = self.pos.x - cp.x wrapped into [-ww<<5/2, ww<<5/2) using [self.world worldWidthMacro] and __aeabi_idiv (0xd3ab18, 0xd3ab88, 0xd3ac00, 0xd3ac70); the local helper at 0xd3b1f4 is abs(int) (called at 0xd3acb4) and |dx| must be < 2 (0xd3acbc). Y gate: cp.y == pos.y-1 or cp.y >= pos.y (0xd3ace0, 0xd3ad10). Then five tile probes through tileAtWorldPositionLoaded(x, y, world) @0x00a12f24: t0(pos.x, pos.y-1) must be non-nil && !tileIsSolid && !tileIsHalfDepth(intpair) && tile[3] != 0x60 (0xd3ad60, 0xd3ad88, 0xd3adf8, 0xd3ae10); t1(pos.x, pos.y) non-nil && tile[1] == 2 (0xd3ae84); t2(pos.x-1, pos.y), t3(pos.x+1, pos.y), t4(pos.x, pos.y+1) each !tileIsHalfDepth && tile[3] != 0x60 && !tileIsSolid (0xd3af30 .. 0xd3b094, no nil test on t2/t3/t4). Any failure skips the element; when all five pass the body calls [self remove:0] (0xd3b148, selector cell 0xd3b1ec) and returns.'),
    ),
    dict(
        name='tp_cbcash',
        method='TradePortal -[currentBlockheadCash]',
        types='i8@0:4',
        start=13878820,
        end=13878996,
        disasm='disasm_tradeportal_currentblockheadcash.txt',
        base_add=13878836,
        base_literal=13878992,
        boundary='consecutive IMPs: next method follows at 0x00d3c6d4',
        selectors={
                 0xd3c6cc: (15239364, 'totalCash'),
        },
        imports={
                 0xd3c6c8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd3c6c4: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={},
        instructions=[(13878820, 'push {fp, lr}'), (13878876, 'cmp r0, r3'), (13878960, 'blx r2'), (13878992, 'ldrhteq r3, [r2], -r8')],
        calls=[(13878960, 'blx r2')],
        branches=[(13878884, 'bne', 13878900), (13878896, 'b', 13878968)],
        semantics=('currentBlockheadCash = nil-guarded [self.currentBlockhead totalCash] (InteractionObject.currentBlockhead@56 reached through slot 0x0105cac4): the cmp/beq at 0xd3c65c/0xd3c664 returns 0 when there is no blockhead, otherwise the single objc_msgSend at 0xd3c6b0 answers totalCash.'),
    ),
    dict(
        name='tp_cbcount',
        method='TradePortal -[currentBlockheadCountOfInventoryItemsOfType:]',
        types='i12@0:4i8',
        start=13878996,
        end=13879320,
        disasm='disasm_tradeportal_currentblockheadcountofinventoryitemsoftype.txt',
        base_add=13879012,
        base_literal=13879316,
        boundary='consecutive IMPs: next method follows at 0x00d3c818',
        selectors={
                 0xd3c80c: (15239372, 'countOfInventoryItemsOfType:includeActions:'),
                 0xd3c810: (15239368, 'countOfInventoryItemsWithSpecificDataBOfType:dataB:includeActions:'),
        },
        imports={
                 0xd3c808: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd3c804: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={},
        instructions=[(13878996, 'push {r4, sl, fp, lr}'), (13879084, 'cmp r0, 0x5b'), (13879176, 'str lr, [sp]'), (13879272, 'sxtb r3, r3'), (13879316, 'eorseq r3, r2, r8, lsl 8')],
        calls=[(13879184, 'blx lr'), (13879280, 'blx ip')],
        branches=[(13879064, 'bne', 13879080), (13879076, 'b', 13879288), (13879088, 'bne', 13879196), (13879192, 'b', 13879288)],
        semantics=('currentBlockheadCountOfInventoryItemsOfType: = nil-guarded dispatch on self.currentBlockhead (@56): the itemType argument (0xd3c728) is compared with 0x5b, and itemType 0x5b goes to countOfInventoryItemsWithSpecificDataBOfType:dataB:includeActions: with dataB = 0 (r3 set at 0xd3c734) and includeActions = 0 (stack slot written at 0xd3c788), every other type to countOfInventoryItemsOfType:includeActions: with includeActions = 0 (r3 from 0xd3c7e8); a nil blockhead returns 0 without any call.'),
    ),
    dict(
        name='tp_cbusage',
        method='TradePortal -[currentBlockheadUsageMultiplierForFirstItemOfType:]',
        types='f12@0:4i8',
        start=13879320,
        end=13879524,
        disasm='disasm_tradeportal_currentblockheadusagemultiplierforfirstitemoftype.txt',
        base_add=13879336,
        base_literal=13879520,
        boundary='consecutive IMPs: next method follows at 0x00d3c8e4',
        selectors={
                 0xd3c8dc: (15239376, 'usageMultiplierForFirstItemOfType:'),
        },
        imports={
                 0xd3c8d8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd3c8d4: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={},
        instructions=[(13879320, 'push {fp, lr}'), (13879396, 'vmov.f32 s0, 1'), (13879480, 'blx r3'), (13879520, 'eorseq r3, r2, r4, asr 5')],
        calls=[(13879480, 'blx r3')],
        branches=[(13879388, 'bne', 13879412), (13879408, 'b', 13879492)],
        semantics=('currentBlockheadUsageMultiplierForFirstItemOfType: = nil-guarded [self.currentBlockhead usageMultiplierForFirstItemOfType:itemType] (@56, call at 0xd3c8b8); the nil path loads 1.0f (vmov.f32 s0, #1 at 0xd3c864) into the return slot, so a portal without a current blockhead answers multiplier 1.0.'),
    ),
    dict(
        name='tp_setpaused',
        method='TradePortal -[setPaused:]',
        types='v12@0:4c8',
        start=13879524,
        end=13879736,
        disasm='disasm_tradeportal_setpaused.txt',
        base_add=13879540,
        base_literal=13879732,
        boundary='consecutive IMPs: next method follows at 0x00d3c9b8',
        selectors={
                 0xd3c9b0: (15239304, 'stop'),
        },
        imports={
                 0xd3c9ac: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd3c9a4: (17168484, 'OBJC_IVAR_$_TradePortal.paused', 116),
                 0xd3c9a8: (17168480, 'OBJC_IVAR_$_TradePortal.sound', 112),
        },
        classes={},
        instructions=[(13879524, 'push {r4, sl, fp, lr}'), (13879580, 'strb r0, [r1]'), (13879596, 'ldrsb r0, [r0]'), (13879680, 'blx r3'), (13879732, 'ldrshteq r3, [r2], -r8')],
        calls=[(13879680, 'blx r3')],
        branches=[(13879608, 'beq', 13879708)],
        semantics=('setPaused: stores the byte argument into TradePortal.paused@116 (strb at 0xd3c91c) and, when the stored value read back with ldrsb at 0xd3c92c is non-zero, calls [self.sound stop] (MJSoundManager ivar@112, objc_msgSend at 0xd3c980); no other state is touched and the paused byte is not reset.'),
    ),
    dict(
        name='tp_upgrade',
        method='TradePortal -[upgradeToNextLevel]',
        types='v8@0:4',
        start=13881120,
        end=13882936,
        disasm='disasm_tradeportal_upgradetonextlevel.txt',
        base_add=13881136,
        base_literal=13882928,
        boundary='consecutive IMPs: next method follows at 0x00d3d638',
        selectors={
                 0xd3d5f0: (15239284, 'instance'),
                 0xd3d5f4: (15239288, 'multiSoundNamed:'),
                 0xd3d5fc: (15239292, 'playAtPosition:'),
                 0xd3d604: (15239276, 'objectType'),
                 0xd3d608: (15239280, 'dynamicWorldChangedAtPos:objectType:'),
                 0xd3d614: (15239388, 'updateTradePortalUIs'),
                 0xd3d618: (15239384, 'uiManager'),
                 0xd3d62c: (15239296, 'addParticleAtPos:velocity:color:gravityType:life:scale:center:'),
        },
        imports={
                 0xd3d5f8: (16441960, '__CFConstantStringClassReference'),
                 0xd3d610: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd3d5dc: (17168476, 'OBJC_IVAR_$_TradePortal.level', 132),
                 0xd3d5e0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd3d5e4: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xd3d600: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd3d60c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xd3d5ec: (15251300, 'OBJC_CLASS_$_MJSoundManager'),
                 0xd3d620: (15251304, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(13881120, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13881172, 'cmp r0, 5'), (13881252, 'str r6, [lr, r4]'), (13881404, 'bl method.Vector2.Vector2_float__float_'), (13881648, 'bl method.Vector.Vector_float__float__float_'), (13881672, 'cmp r0, 8'), (13881780, 'bl method.Vector.Vector_float__float__float__float_'), (13881948, 'bl method.Vector.operator_Vector_'), (13882052, 'bl method.Vector.Vector_float__float__float_'), (13882424, 'bl loc.imp.objc_msgSend'), (13882552, 'blx r2'), (13882616, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13882732, 'strb r0, [r1]'), (13882932, 'andeq r0, r0, r0')],
        calls=[(13881308, 'bl loc.imp.objc_msgSend'), (13881332, 'bl loc.imp.objc_msgSend'), (13881404, 'bl method.Vector2.Vector2_float__float_'), (13881432, 'bl loc.imp.objc_msgSend'), (13881504, 'bl loc.imp.objc_msgSend'), (13881540, 'bl loc.imp.objc_msgSend'), (13881648, 'bl method.Vector.Vector_float__float__float_'), (13881680, 'bl 0xd37798'), (13881780, 'bl method.Vector.Vector_float__float__float__float_'), (13881816, 'bl loc.imp.objc_msgSend'), (13881824, 'bl 0xd37798'), (13881860, 'bl 0xd37798'), (13881908, 'bl method.Vector.Vector_float__float__float_'), (13881948, 'bl method.Vector.operator_Vector_'), (13881952, 'bl 0xd37798'), (13881996, 'bl 0xd37798'), (13882052, 'bl method.Vector.Vector_float__float__float_'), (13882088, 'bl 0xd37798'), (13882128, 'bl 0xd37798'), (13882424, 'bl loc.imp.objc_msgSend'), (13882536, 'blx r3'), (13882552, 'blx r2'), (13882616, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(13881180, 'bge', 13882836), (13881676, 'bge', 13882448), (13882440, 'b', 13881668), (13882636, 'beq', 13882832), (13882680, 'bhi', 13882824), (13882736, 'b', 13882828), (13882772, 'b', 13882828), (13882788, 'b', 13882828), (13882804, 'b', 13882828), (13882820, 'b', 13882828), (13882824, 'b', 13882828), (13882828, 'b', 13882832), (13882832, 'b', 13882836)],
        semantics=('upgradeToNextLevel: level@132 >= 5 returns immediately (0xd3cf54); otherwise level++ (0xd3cfa4). Sound: [MJSoundManager instance] then multiSoundNamed:@"upgrade.wav" (CFString 0xfae268) and playAtPosition:Vector2(pos.x, pos.y) (0xd3cfdc, 0xd3cff4, 0xd3d03c, 0xd3d058). Then [self.dynamicWorld@8 dynamicWorldChangedAtPos:(pos.x, pos.y) objectType:] with the objectType on the stack (0xd3d0c4) and self.updateNeedsToBeSent@49 = 1 (0xd3d0dc). Particles: base Vector v0 = (pos.x+0.5, pos.y, -0.5) (0xd3d130), loop i < 8 (0xd3d148): r = lrand48()/2147483648.0f - the called thunk 0xd37798 is {push {fp,lr}; mov fp,sp; bl lrand48@plt; pop {fp,pc}}, i.e. plain lrand48() (corrects the E9a batch description, which called 0xd37798 a price-hash helper) - colour Vector4 (r*1.5+0.231373, r*1.5+0.347059, 1.0, 0.5) (0xd3d1b4), velocity ((r-0.5)*4, (r-0.3)*4, 0) (0xd3d2c4), position v0+(r-0.5, 2r, 0) via Vector::operator+ (0xd3d25c), then [ParticleEmitter instance addParticleAtPos:velocity:color:gravityType:2 life:r*4+1 scale:r*4+4 center:v0] (0xd3d438). Tail: [[self.world uiManager] updateTradePortalUIs] (0xd3d4a8, 0xd3d4b8); tile = tileAtWorldPositionLoaded(pos.x, pos.y-1, world) and when non-nil switch (level-1, 0..4 through the 5-word table at 0xd3d550) writes tile[0] = {0x3d, 0x3e, 0x3f, 0x40, 0x41} (0xd3d56c).'),
    ),
    dict(
        name='tp_sell',
        method='TradePortal -[sellItem:atTotalPrice:count:usageMultiplier:]',
        types='v24@0:4i8i12i16f20',
        start=13882936,
        end=13884656,
        disasm='disasm_tradeportal_sellitem.txt',
        base_add=13882952,
        base_literal=13884648,
        boundary='consecutive IMPs: next method follows at 0x00d3dcf0',
        selectors={
                 0xd3dc70: (15239396, 'count'),
                 0xd3dc74: (15239392, 'subtractItemsFromInventoryOfType:count:dataB:'),
                 0xd3dc80: (15239400, 'isClientBlockheadBeingControlledByServer'),
                 0xd3dc88: (15239404, 'reportAchievementWithIdentifier:'),
                 0xd3dc90: (15239156, 'objectForKey:'),
                 0xd3dc9c: (15239340, 'stringWithFormat:'),
                 0xd3dca4: (15239160, 'doubleValue'),
                 0xd3dcb0: (15239164, 'numberWithDouble:'),
                 0xd3dcb4: (15239168, 'setObject:forKey:'),
                 0xd3dcb8: (15239408, 'updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:'),
                 0xd3dcc4: (15239332, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0xd3dcc8: (15239276, 'objectType'),
                 0xd3dccc: (15239280, 'dynamicWorldChangedAtPos:objectType:'),
                 0xd3dcd8: (15239284, 'instance'),
                 0xd3dcdc: (15239288, 'multiSoundNamed:'),
                 0xd3dce4: (15239412, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0xd3dc6c: (17151904, 'objc_msgSend'),
                 0xd3dc78: (16442088, '__CFConstantStringClassReference'),
                 0xd3dc84: (16442040, '__CFConstantStringClassReference'),
                 0xd3dc98: (16442056, '__CFConstantStringClassReference'),
                 0xd3dce0: (16442072, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd3dc68: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xd3dc7c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xd3dc8c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd3dc94: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128),
                 0xd3dcbc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd3dcc0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd3dcd0: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={
                 0xd3dca0: (15251308, 'OBJC_CLASS_$_NSString'),
                 0xd3dcac: (15251284, 'OBJC_CLASS_$_NSNumber'),
                 0xd3dcd4: (15251300, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(13882936, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13883024, 'beq 0xd3dc54'), (13883032, 'cmp r0, 0xa7'), (13883084, 'mvn r0, 0'), (13883216, 'blx ip'), (13883232, 'blx r2'), (13883252, 'bne 0xd3dc3c'), (13883448, 'blx ip'), (13883580, 'blx r5'), (13883720, 'vmul.f64 d1, d2, d1'), (13883740, 'bpl 0xd3d96c'), (13883964, 'bl loc.imp.objc_msgSend'), (13884196, 'bl loc.imp.objc_msgSend'), (13884320, 'mov r3, 1'), (13884652, 'andeq r0, r0, r0')],
        calls=[(13883216, 'blx ip'), (13883232, 'blx r2'), (13883352, 'blx r2'), (13883448, 'blx ip'), (13883580, 'blx r5'), (13883632, 'blx ip'), (13883696, 'blx r2'), (13883880, 'bl loc.imp.objc_msgSend'), (13883916, 'bl loc.imp.objc_msgSend'), (13883964, 'bl loc.imp.objc_msgSend'), (13884092, 'bl sym.makeIntpair_int__int_'), (13884196, 'bl loc.imp.objc_msgSend'), (13884260, 'bl loc.imp.objc_msgSend'), (13884296, 'bl loc.imp.objc_msgSend'), (13884344, 'bl loc.imp.objc_msgSend'), (13884368, 'bl loc.imp.objc_msgSend'), (13884424, 'bl method.Vector2.Vector2_float__float_'), (13884468, 'bl loc.imp.objc_msgSend'), (13884488, 'bl sym.imp.NSLog')],
        branches=[(13883024, 'beq', 13884500), (13883036, 'beq', 13883080), (13883052, 'beq', 13883080), (13883064, 'beq', 13883080), (13883076, 'bne', 13883084), (13883080, 'b', 13884496), (13883100, 'bne', 13883112), (13883252, 'bne', 13884476), (13883288, 'bne', 13883452), (13883364, 'bne', 13883452), (13883652, 'beq', 13883708), (13883740, 'bpl', 13883756), (13883752, 'b', 13883804), (13883780, 'ble', 13883800), (13883800, 'b', 13883804), (13884472, 'b', 13884492), (13884492, 'b', 13884496), (13884496, 'b', 13884500)],
        semantics=('sellItem:atTotalPrice:count:usageMultiplier: returns without effect when currentBlockhead@56 is nil (0xd3d690) or when itemType is one of {0xa7 (0xd3d698), 0x444 (0xd3d6a0), 0xa6 (0xd3d6b4), 0x104 (0xd3d6c0)} - the same set the sibling buyItem: handles as a coin swap. dataB starts as -1 (mvn r0, 0 at 0xd3d6cc) and becomes 0 when itemType == 0x5b (0xd3d6d8, 0xd3d6e0). It then calls [currentBlockhead subtractItemsFromInventoryOfType:count:dataB:] (0xd3d750) and [result count] (0xd3d760); soldCount != count logs CFString@0xfae2e8 "Error trying to subtract items to sell." (0xd3dc48) and returns. Otherwise, only when !isNet@52 (0xd3d790) and ![currentBlockhead isClientBlockheadBeingControlledByServer] (0xd3d7d8), it reports [self.world reportAchievementWithIdentifier:@"grp.trade" (0xfae2b8)] (0xd3d838). key = [NSString stringWithFormat:@"%d" (0xfae2c8), itemType] (0xd3d8bc); the price multiplier is [self.localPriceOffsets@128[key] doubleValue] (or 1.0 when absent, 0xd3d864) multiplied by 0.997 (double 0x3fefe76c8b439581 at 0xd3dc60, vmul at 0xd3d948) and clamped to [0.5, 2.0] (0xd3d93c, 0xd3d960, 0xd3d970, 0xd3d98c), then written back with numberWithDouble:; [self.world updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:] (0xd3da3c) receives the key and r3 = the raw float bits of usageMultiplier. The returned price is split as price/10000 (0xd3da44 magic 0x68db8bad) and price%10000 (0xd3da6c 0x2710), then [self.dynamicWorld@8 createFreeBlockAtPosition:makeIntpair(pos.x, pos.y+1) ofType:298 (0x12a) dataA:price/10000 dataB:price%10000 subItems:0 dynamicObjectSaveDict:0 hovers:0 playSound:4 priorityBlockhead:currentBlockhead] (0xd3db24; both halves are read back with ldrh, so they are 16-bit); then dynamicWorldChangedAtPos:pos objectType:0x32, self.updateNeedsToBeSent@49 = 1 (0xd3dba0) and [MJSoundManager instance multiSoundNamed:@"sale.wav" (0xf4ef89) playAtPosition:pos afterDelay:0].'),
    ),
    dict(
        name='tp_buy',
        method='TradePortal -[buyItem:atTotalPrice:count:]',
        types='v20@0:4i8i12i16',
        start=13884656,
        end=13887452,
        disasm='disasm_tradeportal_buyitem.txt',
        base_add=13884672,
        base_literal=13887448,
        boundary='consecutive IMPs: next method follows at 0x00d3e7dc',
        selectors={
                 0xd3e748: (15239364, 'totalCash'),
                 0xd3e750: (15239400, 'isClientBlockheadBeingControlledByServer'),
                 0xd3e758: (15239404, 'reportAchievementWithIdentifier:'),
                 0xd3e760: (15239156, 'objectForKey:'),
                 0xd3e76c: (15239340, 'stringWithFormat:'),
                 0xd3e774: (15239420, 'subtractCash:'),
                 0xd3e778: (15239160, 'doubleValue'),
                 0xd3e77c: (15239408, 'updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:'),
                 0xd3e780: (15239168, 'setObject:forKey:'),
                 0xd3e784: (15239164, 'numberWithDouble:'),
                 0xd3e798: (15239284, 'instance'),
                 0xd3e79c: (15239288, 'multiSoundNamed:'),
                 0xd3e7a8: (15239412, 'playAtPosition:afterDelay:'),
                 0xd3e7b0: (15239276, 'objectType'),
                 0xd3e7b4: (15239280, 'dynamicWorldChangedAtPos:objectType:'),
                 0xd3e7bc: (15239332, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0xd3e7c0: (15239372, 'countOfInventoryItemsOfType:includeActions:'),
                 0xd3e7c4: (15239396, 'count'),
                 0xd3e7c8: (15239416, 'subtractItemsFromInventoryOfType:count:'),
        },
        imports={
                 0xd3e744: (17151904, 'objc_msgSend'),
                 0xd3e754: (16442040, '__CFConstantStringClassReference'),
                 0xd3e768: (16442056, '__CFConstantStringClassReference'),
                 0xd3e7a0: (16442072, '__CFConstantStringClassReference'),
                 0xd3e7cc: (16442104, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd3e740: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xd3e74c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xd3e75c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd3e764: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128),
                 0xd3e78c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xd3e7a4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd3e7ac: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0xd3e770: (15251308, 'OBJC_CLASS_$_NSString'),
                 0xd3e788: (15251284, 'OBJC_CLASS_$_NSNumber'),
                 0xd3e790: (15251300, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(13884656, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13884736, 'beq 0xd3e738'), (13884744, 'cmp r0, 0xa7'), (13884992, 'ldr r3, [0x00d3e7c0]'), (13885072, 'blt 0xd3e0c8'), (13885208, 'bne 0xd3e0b4'), (13885380, 'mov r1, 4'), (13885448, 'ldr r0, [0x00d3e790]'), (13885724, 'bgt 0xd3e730'), (13885860, 'ldr r3, [0x00d3e758]'), (13885996, 'ldr sl, [0x00d3e774]'), (13886292, 'bpl 0xd3e364'), (13886636, 'bl sym.itemTypeIsSowable_ItemType_'), (13886852, 'mov r3, 4'), (13887276, 'strb r2, [r0]'), (13887448, 'eorseq r1, r2, ip, ror 27')],
        calls=[(13885060, 'blx ip'), (13885172, 'blx ip'), (13885188, 'blx r2'), (13885324, 'bl sym.makeIntpair_int__int_'), (13885428, 'bl loc.imp.objc_msgSend'), (13885480, 'bl loc.imp.objc_msgSend'), (13885504, 'bl loc.imp.objc_msgSend'), (13885568, 'bl method.Vector2.Vector2_float__float_'), (13885612, 'bl loc.imp.objc_msgSend'), (13885632, 'bl sym.imp.NSLog'), (13885704, 'blx r2'), (13885824, 'blx r2'), (13885920, 'blx ip'), (13886092, 'blx sl'), (13886132, 'blx ip'), (13886184, 'blx ip'), (13886248, 'blx r2'), (13886520, 'blx r7'), (13886568, 'blx ip'), (13886616, 'blx ip'), (13886636, 'bl sym.itemTypeIsSowable_ItemType_'), (13886788, 'bl sym.makeIntpair_int__int_'), (13886912, 'bl loc.imp.objc_msgSend'), (13887004, 'bl loc.imp.objc_msgSend'), (13887028, 'bl loc.imp.objc_msgSend'), (13887100, 'bl method.Vector2.Vector2_float__float_'), (13887144, 'bl loc.imp.objc_msgSend'), (13887216, 'bl loc.imp.objc_msgSend'), (13887252, 'bl loc.imp.objc_msgSend')],
        branches=[(13884736, 'beq', 13887288), (13884748, 'beq', 13884792), (13884764, 'beq', 13884792), (13884776, 'beq', 13884792), (13884788, 'bne', 13885644), (13884820, 'bne', 13884852), (13884848, 'b', 13884976), (13884860, 'bne', 13884892), (13884888, 'b', 13884972), (13884904, 'bne', 13884944), (13884940, 'b', 13884968), (13884968, 'b', 13884972), (13884972, 'b', 13884976), (13885072, 'blt', 13885640), (13885208, 'bne', 13885620), (13885236, 'bge', 13885448), (13885444, 'b', 13885224), (13885616, 'b', 13885636), (13885636, 'b', 13885640), (13885640, 'b', 13887284), (13885724, 'bgt', 13887280), (13885760, 'bne', 13885924), (13885836, 'bne', 13885924), (13886204, 'beq', 13886260), (13886292, 'bpl', 13886308), (13886304, 'b', 13886356), (13886332, 'ble', 13886352), (13886352, 'b', 13886356), (13886648, 'beq', 13886664), (13886688, 'bge', 13886944), (13886700, 'beq', 13886916), (13886916, 'b', 13886920), (13886932, 'b', 13886676), (13887280, 'b', 13887284), (13887284, 'b', 13887288)],
        semantics=('buyItem:atTotalPrice:count: returns when currentBlockhead@56 is nil (0xd3dd40). itemType in {0xa7, 0x444, 0xa6, 0x104} takes the coin-swap fast path (0xd3dd48 .. 0xd3dd74): per case {blocks, required, spawned, consumed} = 0xa6 {100 x 0xa7 -> 1 x 0xa6} (0xd3dd98), 0x104 {1 x 0xa7 -> 100 required} (0xd3ddc0), 0x444 {1 x 0xa6 -> 100 x 0xa7} (0xd3ddec), 0xa7 {100 x 0x104 -> 1 required} (0xd3de10); it gates on [currentBlockhead countOfInventoryItemsOfType:includeActions:0] >= required (0xd3de40, 0xd3de90) and on [currentBlockhead subtractItemsFromInventoryOfType:count:] == required, otherwise logs CFString@0xfae2f8 "Error trying to subtract coins to trade." (0xd3df18) and returns; then count x [dynamicWorld createFreeBlockAtPosition:(pos.x, pos.y+1) ofType:... playSound:4 priorityBlockhead:currentBlockhead] (0xd3dfac, 0xd3dfc4, 0xd3dff4) followed by [MJSoundManager instance multiSoundNamed:@"sale.wav" playAtPosition:pos afterDelay:0] (0xd3e008). Every other itemType takes the priced path (0xd3e0cc): cash = [currentBlockhead totalCash] (0xd3e0d8) and atTotalPrice > cash returns (0xd3e11c); only when !isNet@52 && ![currentBlockhead isClientBlockheadBeingControlledByServer] it reports [self.world reportAchievementWithIdentifier:@"grp.trade"] (0xd3e1a4); [currentBlockhead subtractCash:atTotalPrice] (0xd3e22c); key = [NSString stringWithFormat:@"%d", itemType] (0xd3e768); the multiplier is [localPriceOffsets@128[key] doubleValue] (1.0 when absent, 0xd3e20c) divided by 0.997 (0xd3e338, 0xd3e5d8) and clamped to [0.5, 2.0] (0xd3e354, 0xd3e37c), stored back through numberWithDouble: and pushed as [self.world updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:-1.0f] (0xd3e39c); dataA = dataB = itemTypeIsSowable(itemType) ? 0x7f : 0 (0xd3e4ac, 0xd3e4bc); then for i < count, skipping itemType 11 (0xd3e4e8), [dynamicWorld createFreeBlockAtPosition:(pos.x, pos.y+1) ofType:itemType dataA:dataA dataB:dataB ... playSound:4 priorityBlockhead:currentBlockhead] (0xd3e584); the tail is the sound, [dynamicWorld dynamicWorldChangedAtPos:pos objectType:[self objectType]] and self.updateNeedsToBeSent@49 = 1 (0xd3e72c).'),
    ),
    dict(
        name='tp_upgradecraft',
        method='TradePortal -[upgradeCraftableItem]',
        types='{CraftableItem=ii[8i][8i]iiiSSi[8i]}8@0:4',
        start=13887452,
        end=13888340,
        disasm='disasm_tradeportal_upgradecraftableitem.txt',
        base_add=13887468,
        base_literal=13888336,
        boundary='consecutive IMPs: next method follows at 0x00d3eb54',
        selectors={
                 0xd3eb40: (15239424, 'expertMode'),
        },
        imports={
                 0xd3eb3c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd3eb44: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd3eb48: (17168476, 'OBJC_IVAR_$_TradePortal.level', 132),
        },
        classes={},
        instructions=[(13887452, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13887672, 'andeq r0, r0, r4, lsl r0'), (13887692, 'ldr r0, [0x00d3eb3c]'), (13887808, 'ldr r0, [0x00d3eb3c]'), (13887924, 'ldr r0, [0x00d3eb3c]'), (13888048, 'ldr r0, [0x00d3eb3c]'), (13888176, 'ldr r0, [0x00d3eb3c]'), (13888336, 'eorseq r1, r2, r0, lsl 6')],
        calls=[(13887584, 'blx ip'), (13887776, 'blx r2'), (13887892, 'blx r2'), (13888008, 'blx r2'), (13888144, 'blx r2'), (13888272, 'blx r2')],
        branches=[(13887596, 'beq', 13887612), (13887648, 'bhi', 13888304), (13887788, 'beq', 13887804), (13887804, 'b', 13888308), (13887904, 'beq', 13887920), (13887920, 'b', 13888308), (13888020, 'beq', 13888044), (13888044, 'b', 13888308), (13888156, 'beq', 13888172), (13888172, 'b', 13888308), (13888284, 'beq', 13888300), (13888300, 'b', 13888308), (13888304, 'b', 13888308)],
        semantics=('upgradeCraftableItem returns the CraftableItem struct by value: it writes the constant header {0x84@0x00 at 0xd3e828, 1@0x04, 0x0b@0x10, 1@0x28 at 0xd3e838} and, when [world expertMode] (call at 0xd3e860) answers non-zero, 0x0a@0x28 (0xd3e878); then switch (self.level@132, 0..4 selected by the 5-word jump table at 0xd3e8b8 -> 0xd3e8cc/0xd3e940/0xd3e9b4/0xd3ea30/0xd3eab0) sets the item type at +8 and the two counts at +0x2c/+0x30: L0 {0x57, 0x0a, 0x0a}, L1 {0x56, 0x14, 0x14}, L2 {0x4c, 0x32, 0x32}, L3 {0x4b, 1, 0x64 with 0x104@0x0c}, L4 {0x58, 0x0a, 0xc8 with 0x104@0x0c}; after each case a second [world expertMode] probe overrides the count: L0 -> 0x32, L1 -> 0x63, L2 -> 0x104@0x0c + count 5, L3 -> 0x14, L4 -> 0x63; level > 4 falls through to the epilogue with only the header written. The struct consumed by takeItemsFromBlockheadForUpgradeToNextLevel is 0x7c bytes with types[]@+8, reqCounts[]@+0x28, nItems@+0x48.'),
    ),
    dict(
        name='tp_takeitems',
        method='TradePortal -[takeItemsFromBlockheadForUpgradeToNextLevel]',
        types='c8@0:4',
        start=13888340,
        end=13890444,
        disasm='disasm_tradeportal_takeitemsfromblockhead.txt',
        base_add=13888356,
        base_literal=13890440,
        boundary='consecutive IMPs: next method follows at 0x00d3f38c',
        selectors={
                 0xd3f324: (15239428, 'upgradeCraftableItem'),
                 0xd3f330: (15239460, 'displayInterstitialForTag:'),
                 0xd3f334: (15239456, 'viewController'),
                 0xd3f338: (15239452, 'delegate'),
                 0xd3f33c: (15239448, 'sharedApplication'),
                 0xd3f344: (15239396, 'count'),
                 0xd3f348: (15239416, 'subtractItemsFromInventoryOfType:count:'),
                 0xd3f354: (15239400, 'isClientBlockheadBeingControlledByServer'),
                 0xd3f358: (15239360, 'isEqualToString:'),
                 0xd3f35c: (15239440, 'stringFromMD5'),
                 0xd3f364: (15239340, 'stringWithFormat:'),
                 0xd3f36c: (15239436, 'amountString'),
                 0xd3f370: (15239284, 'instance'),
                 0xd3f378: (15239432, 'amount'),
                 0xd3f384: (15239444, 'modify:modifyString:'),
        },
        imports={
                 0xd3f328: (16442152, '__CFConstantStringClassReference'),
                 0xd3f32c: (17151904, 'objc_msgSend'),
                 0xd3f360: (16442120, '__CFConstantStringClassReference'),
                 0xd3f380: (16442136, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd3f34c: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={
                 0xd3f340: (15251316, 'OBJC_CLASS_$_UIApplication'),
                 0xd3f368: (15251308, 'OBJC_CLASS_$_NSString'),
                 0xd3f374: (15251312, 'OBJC_CLASS_$_CrystalManager'),
        },
        instructions=[(13888340, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13888420, 'bl loc.imp.objc_msgSend_stret'), (13888432, 'movw r2, 0x7c'), (13888520, 'cmp r1, 0xb'), (13888812, 'blx sl'), (13888920, 'blx lr'), (13889100, 'str r0, [fp, -0xb4]'), (13889148, 'strb r0, [fp, -0x1d]'), (13889388, 'add r0, r0, 0x49'), (13889796, 'strb r0, [fp, -0xa9]'), (13890032, 'blx ip'), (13890104, 'strb r0, [fp, -0x1d]'), (13890312, 'blx r3'), (13890440, 'eorseq r0, r2, r8, lsl 31')],
        calls=[(13888420, 'bl loc.imp.objc_msgSend_stret'), (13888456, 'bl sym.imp.memset'), (13888592, 'blx r2'), (13888812, 'blx sl'), (13888828, 'blx r2'), (13888864, 'blx r3'), (13888880, 'blx r2'), (13888920, 'blx lr'), (13888936, 'blx r2'), (13888968, 'blx r3'), (13889064, 'blx lr'), (13889080, 'blx r2'), (13889332, 'bl loc.imp.objc_msgSend'), (13889348, 'bl loc.imp.objc_msgSend'), (13889432, 'bl loc.imp.objc_msgSend'), (13889448, 'bl loc.imp.objc_msgSend'), (13889476, 'bl loc.imp.objc_msgSend'), (13889508, 'bl loc.imp.objc_msgSend'), (13889532, 'bl loc.imp.objc_msgSend'), (13889548, 'bl loc.imp.objc_msgSend'), (13889616, 'blx ip'), (13889632, 'blx r2'), (13889664, 'blx r3'), (13889760, 'blx lr'), (13889776, 'blx r2'), (13890032, 'blx ip'), (13890072, 'blx r3'), (13890260, 'blx r2'), (13890276, 'blx r2'), (13890292, 'blx r2'), (13890312, 'blx r3')],
        branches=[(13888404, 'beq', 13888428), (13888424, 'b', 13888460), (13888492, 'bge', 13889832), (13888528, 'bne', 13889812), (13888604, 'bne', 13889808), (13888980, 'beq', 13889096), (13889092, 'bne', 13889104), (13889140, 'ble', 13889156), (13889152, 'b', 13890328), (13889188, 'ble', 13889804), (13889676, 'beq', 13889792), (13889788, 'bne', 13889800), (13889800, 'b', 13889804), (13889804, 'b', 13889808), (13889808, 'b', 13889812), (13889812, 'b', 13889816), (13889828, 'b', 13888480), (13889852, 'bge', 13890136), (13889888, 'beq', 13890116), (13890096, 'ble', 13890112), (13890108, 'b', 13890328), (13890112, 'b', 13890116), (13890116, 'b', 13890120), (13890132, 'b', 13889840), (13890144, 'beq', 13890320)],
        semantics=('takeItemsFromBlockheadForUpgradeToNextLevel returns BOOL. It first calls [self upgradeCraftableItem] through objc_msgSend_stret into a 0x7c-byte buffer at fp-0xa8 (0xd3eba4) and memsets 0x7c bytes when self is nil (0xd3ebb0); the struct layout used here is types[]@+8, reqCounts[]@+0x28, nItems@+0x48. Pass 1 (0xd3ebe0, i < nItems) only acts on type 11 (0xd3ec08) and only when ![currentBlockhead@56 isClientBlockheadBeingControlledByServer] (0xd3ec50): it takes [CrystalManager instance] (0xd3ed2c) and its amount/amountString (0xd3ed70); when amountString != MD5([NSString stringWithFormat:@"7acfe93afc08%dc65ae2c54ecaf07f" (0xfae308), amount]) (0xd3ed98, 0xd3eda8, 0xd3edc8) the amount is forced to 0 (0xd3ee4c); reqCounts[i] > amount returns NO (0xd3ee7c); otherwise for reqCounts[i] > 0 it calls [instance modify:reqCounts[i] modifyString:MD5(stringWithFormat:@"7acfe93afc08c%d65ae2c54ecaf07f" (0xfae318), amount - reqCounts[i] + 73)] (0xd3ef6c, 0xd3efe4) and a second fingerprint check against the new amountString sets a cheat flag byte (0xd3f104). Pass 2 (0xd3f130) skips type 11 and calls [currentBlockhead subtractItemsFromInventoryOfType:types[i] count:reqCounts[i]] (0xd3f1f0), returning NO when reqCounts[i] - [result count] > 0 (0xd3f218, 0xd3f238). When the cheat flag is set the tail is [[[UIApplication sharedApplication] delegate] viewController] displayInterstitialForTag:@"Hax" (0xfae328)] (0xd3f308) and the method returns the pass-2 result (YES).'),
    ),
    dict(
        name='tp_randomize',
        method='TradePortal -[randomizeLocalTradeOffsets]',
        types='v8@0:4',
        start=13890656,
        end=13891500,
        disasm='disasm_tradeportal_randomizelocaloffsets.txt',
        base_add=13890672,
        base_literal=13891496,
        boundary='consecutive IMPs: next method follows at 0x00d3f7ac',
        selectors={
                 0xd3f770: (15239276, 'objectType'),
                 0xd3f774: (15239280, 'dynamicWorldChangedAtPos:objectType:'),
                 0xd3f784: (15239168, 'setObject:forKey:'),
                 0xd3f788: (15239464, 'numberWithFloat:'),
                 0xd3f798: (15239340, 'stringWithFormat:'),
        },
        imports={
                 0xd3f780: (17151904, 'objc_msgSend'),
                 0xd3f794: (16442056, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd3f760: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xd3f764: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd3f76c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd3f790: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128),
        },
        classes={
                 0xd3f78c: (15251284, 'OBJC_CLASS_$_NSNumber'),
                 0xd3f79c: (15251308, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(13890656, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13890812, 'ldr r1, [r1]'), (13890880, 'bl 0xd37798'), (13890948, 'bl sym.imp.__wrap_powf'), (13891412, 'strb r2, [r0]'), (13891496, 'eorseq r0, r2, ip, ror r6')],
        calls=[(13890880, 'bl 0xd37798'), (13890948, 'bl sym.imp.__wrap_powf'), (13891092, 'blx r6'), (13891156, 'blx r3'), (13891204, 'blx ip'), (13891352, 'bl loc.imp.objc_msgSend'), (13891388, 'bl loc.imp.objc_msgSend')],
        branches=[(13890708, 'bge', 13891244), (13890756, 'beq', 13891224), (13890832, 'bne', 13890880), (13890864, 'blt', 13890876), (13890876, 'b', 13891220), (13891220, 'b', 13890732), (13891224, 'b', 13891228), (13891240, 'b', 13890700)],
        semantics=('randomizeLocalTradeOffsets walks the PIC-relative trade table at 0x00e18ee0 (cell 0xd3f778 holds -0x246c14; entry = table + level*0x360 + slot*0x90 where level runs 1..8 and slot 0..5, and the word at +0 is the occupancy test read at 0xd3f4fc): for every non-zero entry it calls the thunk at 0xd37798 (0xd3f540) which is {push {fp,lr}; mov fp,sp; bl lrand48@plt; pop {fp,pc}} - i.e. plain lrand48(), not the price-hash helper the E9a batch description assumed - and computes powf(0.8f, ((float)v / 2147483648.0f - 0.5f) * 10.0f) with the pool constants 0x3f4ccccd = 0.8f and 0x4f000000 = 2^31 at 0xd3f7a0/0xd3f7a4 and __wrap_powf at 0xd3f584 (10.0f / 0.5f immediates at 0xd3f54c / 0xd3f550). The result becomes [NSNumber numberWithFloat:] (class cell 0xd3f78c) and is stored by [self.localPriceOffsets setObject:forKey:] (ivar@128, cell 0xd3f784) under [NSString stringWithFormat: CFString@0x00fae2c8] (class cell 0xd3f79c); a zero entry advances the slot (0xd3f514) and marks the level exhausted at slot >= 6 (0xd3f534). Tail (0xd3f6ac): dyW = self.dynamicWorld@8, objType = [dyW objectType] (0xd3f718), [dyW dynamicWorldChangedAtPos:(self.pos.x, self.pos.y) objectType:objType] (0xd3f73c), then self.updateNeedsToBeSent@49 = 1 (strb at 0xd3f754).'),
    ),
    dict(
        name='tp_issell',
        method='TradePortal -[isSellInteraction]',
        types='c8@0:4',
        start=13891828,
        end=13891888,
        disasm='disasm_tradeportal_issellinteraction.txt',
        base_add=13891836,
        base_literal=13891884,
        boundary='body trimmed at the next IMP 0x00d3f930 (ARM.exidx over-covers into isMissionInteraction)',
        selectors={},
        imports={},
        ivars={
                 0xd3f928: (17168500, 'OBJC_IVAR_$_TradePortal.isSellInteraction', 136),
        },
        classes={},
        instructions=[(13891828, 'sub sp, sp, 8'), (13891868, 'ldrsb r0, [r0]'), (13891884, 'ldrshteq r0, [r2], -r0')],
        calls=[],
        branches=[],
        semantics=('isSellInteraction = ldrsb of the TradePortal.isSellInteraction byte at @136 (0xd3f91c); no call, no branch.'),
    ),
    dict(
        name='tp_ismission',
        method='TradePortal -[isMissionInteraction]',
        types='c8@0:4',
        start=13891888,
        end=13891948,
        disasm='disasm_tradeportal_ismissioninteraction.txt',
        base_add=13891896,
        base_literal=13891944,
        boundary='ARM.exidx end 0x00d3f96c; the next ObjC IMP (Bed -[objectType]) is at 0x00d3fc38',
        selectors={},
        imports={},
        ivars={
                 0xd3f964: (17168504, 'OBJC_IVAR_$_TradePortal.isMissionInteraction', 137),
        },
        classes={},
        instructions=[(13891888, 'sub sp, sp, 8'), (13891928, 'ldrsb r0, [r0]'), (13891944, 'ldrhteq r0, [r2], -r4')],
        calls=[],
        branches=[],
        semantics=('isMissionInteraction = ldrsb of the TradePortal.isMissionInteraction byte at @137 (0xd3f958); the body is byte-identical to isSellInteraction apart from the ivar cell (0xd3f964) and the pool literal.'),
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
        'batch': 'TradePortal economics batch (E9b): trade pricing and settlement - loadPriceOffsets: (price dict rebuild, [0.5, 2.0] clamp), currentBlockhead trio, setPaused:, sellItem:atTotalPrice:count:usageMultiplier:, buyItem:atTotalPrice:count:, upgradeToNextLevel, upgradeCraftableItem (level jump table), takeItemsFromBlockheadForUpgradeToNextLevel, randomizeLocalTradeOffsets (trade-table walk + powf price jitter), worldChanged:(vector<intpair>), isSellInteraction/isMissionInteraction (14 bodies)',
        'claim': ('static bounded-body maps with per-instruction anchors; runtime values, '
                  'the UI consumers and the trade-table contents are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'trade_portal_econ.json')
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
