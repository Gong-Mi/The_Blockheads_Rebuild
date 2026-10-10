#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld breeding/NPC/service cluster (E27).

The DynamicWorld breeding, NPC and service cluster: the NPC breeding-distance
check, the breeding-plant partner scan, the plant/occupant lookups, the NPC
spawn cap, the pause propagation and the blockhead inventory/teleport services:
1 body, 2961 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/BREED_NPC.md for the prose and boundaries.
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
    'bl 0x8ad2a4': 0x008ad2a4,
    'bl 0x8e3ea0': 0x008e3ea0,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__umodsi3': 0x001c2f9c,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
}

SPECS = [
    dict(
        name='wtl_npccloseenoughtobreedw',
        method='DynamicWorld -[npcCloseEnoughToBreedWithNPC:]',
        types='@12@0:4@8',
        start=9384584,
        end=9386880,
        disasm='disasm_worldtileloader_npccloseenoughtobreedwithnpc_.txt',
        base_add=9384600,
        base_literal=9386876,
        boundary='ARM.exidx end 0x008f3b80 (listing bound); next ObjC IMP 0x008f3b80 DynamicWorld -[blockheadOccupiesTileAtPos:ignoreBlockhead:]',
        selectors={
                 0x8f3b4c: (15216168, 'objectType'),
                 0x8f3b5c: (15217064, 'canMate'),
                 0x8f3b60: (15216012, 'pos'),
                 0x8f3b6c: (15216128, 'worldWidthMacro'),
        },
        imports={
                 0x8f3b58: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f3b54: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8f3b64: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9384584, 'push {r4, sl, fp, lr}'), (9384664, 'bl loc.imp.objc_msgSend'), (9385068, 'blx r2'), (9385292, 'sub r2, r3, r2'), (9385652, 'bl loc.imp.objc_msgSend'), (9385968, 'bl sym.imp.__aeabi_idiv'), (9386756, 'b 0x8f3b08'), (9386876, 'rsbseq ip, r6, r4, asr r8')],
        calls=[(9384664, 'bl loc.imp.objc_msgSend'), (9385068, 'blx r2'), (9385136, 'bl loc.imp.objc_msgSend_stret'), (9385172, 'bl sym.imp.memset'), (9385236, 'bl loc.imp.objc_msgSend_stret'), (9385272, 'bl sym.imp.memset'), (9385352, 'bl loc.imp.objc_msgSend'), (9385376, 'bl sym.imp.__aeabi_idiv'), (9385444, 'bl loc.imp.objc_msgSend_stret'), (9385480, 'bl sym.imp.memset'), (9385544, 'bl loc.imp.objc_msgSend_stret'), (9385580, 'bl sym.imp.memset'), (9385652, 'bl loc.imp.objc_msgSend'), (9385736, 'bl loc.imp.objc_msgSend_stret'), (9385772, 'bl sym.imp.memset'), (9385836, 'bl loc.imp.objc_msgSend_stret'), (9385872, 'bl sym.imp.memset'), (9385952, 'bl loc.imp.objc_msgSend'), (9385968, 'bl sym.imp.__aeabi_idiv'), (9386036, 'bl loc.imp.objc_msgSend_stret'), (9386072, 'bl sym.imp.memset'), (9386136, 'bl loc.imp.objc_msgSend_stret'), (9386172, 'bl sym.imp.memset'), (9386244, 'bl loc.imp.objc_msgSend'), (9386328, 'bl loc.imp.objc_msgSend_stret'), (9386364, 'bl sym.imp.memset'), (9386428, 'bl loc.imp.objc_msgSend_stret'), (9386464, 'bl sym.imp.memset'), (9386552, 'bl loc.imp.objc_msgSend_stret'), (9386588, 'bl sym.imp.memset'), (9386652, 'bl loc.imp.objc_msgSend_stret'), (9386688, 'bl sym.imp.memset'), (9386712, 'bl 0x8e3ea0'), (9386728, 'bl 0x8e3ea0'), (9386792, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9384956, 'beq', 9386808), (9385024, 'beq', 9386756), (9385080, 'beq', 9386756), (9385120, 'beq', 9385144), (9385140, 'b', 9385176), (9385220, 'beq', 9385244), (9385240, 'b', 9385276), (9385388, 'blt', 9385684), (9385428, 'beq', 9385452), (9385448, 'b', 9385484), (9385528, 'beq', 9385552), (9385548, 'b', 9385584), (9385680, 'b', 9386492), (9385720, 'beq', 9385744), (9385740, 'b', 9385776), (9385820, 'beq', 9385844), (9385840, 'b', 9385876), (9385980, 'bge', 9386276), (9386020, 'beq', 9386044), (9386040, 'b', 9386076), (9386120, 'beq', 9386144), (9386140, 'b', 9386176), (9386272, 'b', 9386484), (9386312, 'beq', 9386336), (9386332, 'b', 9386368), (9386412, 'beq', 9386436), (9386432, 'b', 9386468), (9386536, 'beq', 9386560), (9386556, 'b', 9386592), (9386636, 'beq', 9386660), (9386656, 'b', 9386692), (9386720, 'bge', 9386752), (9386736, 'bge', 9386752), (9386748, 'b', 9386816), (9386752, 'b', 9386756), (9386756, 'b', 9386760), (9386804, 'b', 9384872)],
        semantics=('npcCloseEnoughToBreedWithNPC: checks the cylindrical-wrap distance between two NPCs. Prologue 0x008f3288 (frame 0x238; base 0x105faf4). Arguments: the two NPCs (r2 the counterpart, self-side via [-0xb0]).\nCounterpart lookup: `[npc objectType]` (ffe23334) -> the ffffe54c map segment (cell 0x8f3b54, 12-byte stride) -> the counterpart node; the ffe236b4 gate (cell 0x8f3b5c) must pass; the candidate pos member ([node+0x10]+8) feeds the position getters (ffe23298 cell 0x8f3b60).\nWrap distance (the E23/E24 family): per coordinate the worldWidthMacro (ffe2330c) `<< 5` + `__aeabi_idiv` with the 2/5 constants and the `rsb r0, r0, 0` negation produce the signed wrap delta (@0x8f353c-0x8f36d0 for x, @0x8f3794-0x8f3920 for y with `sub r1, r2, r1` variants); in-range candidates continue the scan (loop via `std::__1::tree_next`), and the in-range result exits at 0x8f3b04 with the boolean. Epilogue 0x8f3b50 region.\n'),
    ),
    dict(
        name='wtl_findbreedingplantnearp',
        method='DynamicWorld -[findBreedingPlantNearPlant:]',
        types='@12@0:4@8',
        start=9320384,
        end=9322144,
        disasm='disasm_worldtileloader_findbreedingplantnearplant_.txt',
        base_add=9320400,
        base_literal=9322140,
        boundary='ARM.exidx end 0x008e3ea0 (listing bound); next ObjC IMP 0x008e3edc DynamicWorld -[sowPlantNearParent:]',
        selectors={
                 0x8e3e60: (15216144, 'array'),
                 0x8e3e64: (15216168, 'objectType'),
                 0x8e3e70: (15215864, 'count'),
                 0x8e3e74: (15215808, 'objectAtIndex:'),
                 0x8e3e78: (15216776, 'canBreed'),
                 0x8e3e7c: (15216012, 'pos'),
                 0x8e3e88: (15216128, 'worldWidthMacro'),
                 0x8e3e98: (15216008, 'addObject:'),
        },
        imports={
                 0x8e3e6c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e3e68: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8e3e80: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={
                 0x8e3e58: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9320384, 'push {r4, sl, fp, lr}'), (9320460, 'bl loc.imp.objc_msgSend'), (9320888, 'blx r2'), (9321200, 'bl sym.imp.__aeabi_idiv'), (9321804, 'b 0x8e3d50'), (9322140, 'rsbseq ip, r7, ip, lsl r3')],
        calls=[(9320460, 'bl loc.imp.objc_msgSend'), (9320484, 'bl loc.imp.objc_msgSend'), (9320888, 'blx r2'), (9320956, 'bl loc.imp.objc_msgSend_stret'), (9320992, 'bl sym.imp.memset'), (9321056, 'bl loc.imp.objc_msgSend_stret'), (9321092, 'bl sym.imp.memset'), (9321176, 'bl loc.imp.objc_msgSend'), (9321200, 'bl sym.imp.__aeabi_idiv'), (9321276, 'bl loc.imp.objc_msgSend'), (9321376, 'bl loc.imp.objc_msgSend'), (9321392, 'bl sym.imp.__aeabi_idiv'), (9321468, 'bl loc.imp.objc_msgSend'), (9321520, 'bl 0x8e3ea0'), (9321584, 'bl loc.imp.objc_msgSend_stret'), (9321620, 'bl sym.imp.memset'), (9321684, 'bl loc.imp.objc_msgSend_stret'), (9321720, 'bl sym.imp.memset'), (9321736, 'bl 0x8e3ea0'), (9321796, 'blx r3'), (9321840, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9321896, 'blx r2'), (9321916, 'bl 0x8ad2a4'), (9321988, 'blx lr'), (9322008, 'bl sym.imp.__umodsi3'), (9322040, 'blx r3')],
        branches=[(9320776, 'beq', 9321856), (9320844, 'beq', 9321804), (9320900, 'beq', 9321804), (9320940, 'beq', 9320964), (9320960, 'b', 9320996), (9321040, 'beq', 9321064), (9321060, 'b', 9321096), (9321212, 'blt', 9321308), (9321304, 'b', 9321516), (9321404, 'bge', 9321500), (9321496, 'b', 9321508), (9321528, 'bge', 9321800), (9321568, 'beq', 9321592), (9321588, 'b', 9321624), (9321668, 'beq', 9321692), (9321688, 'b', 9321724), (9321744, 'bge', 9321800), (9321800, 'b', 9321804), (9321804, 'b', 9321808), (9321852, 'b', 9320692), (9321904, 'bls', 9322052), (9322048, 'b', 9322060)],
        semantics=("findBreedingPlantNearPlant: finds a same-family breeding partner near a plant. Prologue 0x008e37c0 (frame 0x1a0; base 0x105faf4).\nGate: the plant-eligibility call ffe23594 (cell 0x8e3e78) on the counterpart (sxtb) must pass (@0x8e39b8-0x8e39c4).\nScan: the ffffe54c segment for the plant's type is iterated (pos member + stret getters, std::__1::tree_next @0x8e3d?? region); the wrap-distance math repeats per coordinate (worldWidthMacro<<5 + idiv + the 2/5 constants with sub/rsb variants @0x8e3a88-0x8e3b58 and siblings) with the in-range candidate taken via the found path 0x8e3d4c/0x8e3d80; the counterpart (self-side) filters by the same family first (the class/isKindOfClass pair at 0x8e37e4-0x8e3824). Epilogue.\n"),
    ),
    dict(
        name='wtl_getplantatpos_',
        method='DynamicWorld -[getPlantAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9369336,
        end=9371196,
        disasm='disasm_worldtileloader_getplantatpos_.txt',
        base_add=9369352,
        base_literal=9371192,
        boundary='ARM.exidx end 0x008efe3c (listing bound); next ObjC IMP 0x008efe3c DynamicWorld -[workbenchAtPos:]',
        selectors={
                 0x8efe28: (15216012, 'pos'),
                 0x8efe30: (15216996, 'numberOfOccupiedTilesAbove'),
                 0x8efe34: (15217000, 'numberOfOccupiedTilesBelow'),
        },
        imports={
                 0x8efe2c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8efe1c: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8efe24: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9369336, 'push {r4, r5, fp, lr}'), (9369388, 'cmp r0, 0xa'), (9369420, 'ldr r1, [r2, r1, lsl 2]'), (9370004, 'blx r2'), (9370256, 'sub r0, fp, 0x60'), (9371192, 'rsbseq r0, r7, r4, ror 7')],
        calls=[(9369808, 'bl loc.imp.objc_msgSend_stret'), (9369844, 'bl sym.imp.memset'), (9369916, 'bl loc.imp.objc_msgSend_stret'), (9369952, 'bl sym.imp.memset'), (9370004, 'blx r2'), (9370080, 'bl loc.imp.objc_msgSend_stret'), (9370116, 'bl sym.imp.memset'), (9370168, 'blx r2'), (9370240, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9370668, 'bl loc.imp.objc_msgSend_stret'), (9370704, 'bl sym.imp.memset'), (9370776, 'bl loc.imp.objc_msgSend_stret'), (9370812, 'bl sym.imp.memset'), (9370864, 'blx r2'), (9370940, 'bl loc.imp.objc_msgSend_stret'), (9370976, 'bl sym.imp.memset'), (9371028, 'blx r2'), (9371100, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9369392, 'bge', 9371136), (9369700, 'beq', 9370256), (9369792, 'beq', 9369816), (9369812, 'b', 9369848), (9369860, 'bne', 9370204), (9369900, 'beq', 9369924), (9369920, 'b', 9369956), (9370024, 'blt', 9370204), (9370064, 'beq', 9370088), (9370084, 'b', 9370120), (9370188, 'bgt', 9370204), (9370200, 'b', 9371144), (9370204, 'b', 9370208), (9370252, 'b', 9369616), (9370560, 'beq', 9371116), (9370652, 'beq', 9370676), (9370672, 'b', 9370708), (9370720, 'bne', 9371064), (9370760, 'beq', 9370784), (9370780, 'b', 9370816), (9370884, 'blt', 9371064), (9370924, 'beq', 9370948), (9370944, 'b', 9370980), (9371048, 'bgt', 9371064), (9371060, 'b', 9371144), (9371064, 'b', 9371068), (9371112, 'b', 9370476), (9371116, 'b', 9371120), (9371132, 'b', 9369384)],
        semantics=('getPlantAtPos: returns the plant object at a position for a plant type. Prologue 0x008ef6f8 (frame 0x228; base 0x105faf4). Arguments: plantType (r0), pos pair.\nGate: `if (plantType >= 0xa) return nil` (cmp 0xa @0x8ef72c) - the 10 plant types.\nScan: the SWITCH jump table (cells 0x8efe14 0xffdeaf48 + 0x8efe18 0x7703a8 -> table @ 0x00E4AA3C, dispatch @0x8ef74c) selects the ffffe54c segment; per node the pos member is compared against the argument through the ffe23670/ffe23674 calls (cells 0x8efe30/0x8efe34, @0x8ef994-0x8efa48: `cmp r0, r1` ranges); an in-range node exits at 0x8efe08. The ffffe550 segment repeats the pass (@0x8efa90+, cell 0x8efe24). NULL when nothing matches (@0x8efe00).\n'),
    ),
    dict(
        name='wtl_toomanynpcstospawnmore',
        method='DynamicWorld -[tooManyNPCsToSpawnMoreNearPos:]',
        types='c16@0:4{?=ii}8',
        start=9382836,
        end=9384584,
        disasm='disasm_worldtileloader_toomanynpcstospawnmorenearpos_.txt',
        base_add=9382852,
        base_literal=9384580,
        boundary='ARM.exidx end 0x008f3288 (listing bound); next ObjC IMP 0x008f3288 DynamicWorld -[npcCloseEnoughToBreedWithNPC:]',
        selectors={
                 0x8f3268: (15216012, 'pos'),
                 0x8f3274: (15216128, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0x8f3264: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8f326c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9382836, 'push {r4, r5, fp, lr}'), (9382892, 'cmp r0, 8'), (9382924, 'ldr r1, [r2, r1, lsl 2]'), (9383452, 'bl sym.imp.__aeabi_idiv'), (9384168, 'ldr r0, [sp, 0x5c]'), (9384520, 'movw r0, 0'), (9384580, 'rsbseq ip, r6, r8, lsr 30')],
        calls=[(9383312, 'bl loc.imp.objc_msgSend_stret'), (9383348, 'bl sym.imp.memset'), (9383428, 'bl loc.imp.objc_msgSend'), (9383452, 'bl sym.imp.__aeabi_idiv'), (9383520, 'bl loc.imp.objc_msgSend_stret'), (9383556, 'bl sym.imp.memset'), (9383628, 'bl loc.imp.objc_msgSend'), (9383712, 'bl loc.imp.objc_msgSend_stret'), (9383748, 'bl sym.imp.memset'), (9383828, 'bl loc.imp.objc_msgSend'), (9383844, 'bl sym.imp.__aeabi_idiv'), (9383912, 'bl loc.imp.objc_msgSend_stret'), (9383948, 'bl sym.imp.memset'), (9384020, 'bl loc.imp.objc_msgSend'), (9384104, 'bl loc.imp.objc_msgSend_stret'), (9384140, 'bl sym.imp.memset'), (9384172, 'bl 0x8e3ea0'), (9384236, 'bl loc.imp.objc_msgSend_stret'), (9384272, 'bl sym.imp.memset'), (9384348, 'bl loc.imp.objc_msgSend_stret'), (9384384, 'bl sym.imp.memset'), (9384484, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9382896, 'bge', 9384520), (9383204, 'beq', 9384500), (9383296, 'beq', 9383320), (9383316, 'b', 9383352), (9383464, 'blt', 9383660), (9383504, 'beq', 9383528), (9383524, 'b', 9383560), (9383656, 'b', 9384168), (9383696, 'beq', 9383720), (9383716, 'b', 9383752), (9383856, 'bge', 9384052), (9383896, 'beq', 9383920), (9383916, 'b', 9383952), (9384048, 'b', 9384160), (9384088, 'beq', 9384112), (9384108, 'b', 9384144), (9384180, 'bge', 9384448), (9384220, 'beq', 9384244), (9384240, 'b', 9384276), (9384292, 'blt', 9384448), (9384332, 'beq', 9384356), (9384352, 'b', 9384388), (9384404, 'bgt', 9384448), (9384428, 'ble', 9384444), (9384440, 'b', 9384528), (9384444, 'b', 9384448), (9384448, 'b', 9384452), (9384496, 'b', 9383120), (9384500, 'b', 9384504), (9384516, 'b', 9382888)],
        semantics=('tooManyNPCsToSpawnMoreNearPos: counts the NPC family near a position and compares it against the spawn cap. Prologue 0x008f2bb4 (frame 0x1a0; base 0x105faf4). Arguments: npcType (r0), pos pair.\nGate: `if (npcType >= 8) return false` (cmp 8 @0x8f2bec) - the 8 NPC families.\nScan: the SWITCH jump table (cells 0x8f325c 0xffdeaf28 + 0x8f3260 0x76cee8 -> table @ 0x00E4AA1C, dispatch @0x8f2c0c) selects the ffffe54c segment; per node the pos member goes through the wrap-distance math (worldWidthMacro<<5 + `__aeabi_idiv` + the 2/5 constants + `sub r0, r2, r0`, @0x8f2db8-0x8f2eec and the y sibling) and in-range nodes are counted ([fp,-0xbc]/[-0xc0] accumulators @0x8f2bdc-0x8f2be0); the found count is compared against the cap and the boolean returned (@0x8f3248 exit). \n'),
    ),
    dict(
        name='wtl_setpaused_',
        method='DynamicWorld -[setPaused:]',
        types='v12@0:4c8',
        start=9409920,
        end=9411440,
        disasm='disasm_worldtileloader_setpaused_.txt',
        base_add=9409936,
        base_literal=9411436,
        boundary='ARM.exidx end 0x008f9b70 (listing bound); next ObjC IMP 0x008f9b70 DynamicWorld -[getTreeLifeFractionForPos:]',
        selectors={
                 0x8f9b4c: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8f9b54: (15217132, 'setPaused:'),
        },
        imports={
                 0x8f9b48: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f9b50: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8f9b60: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9409920, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9409968, 'ldr r7, [0x008f9b50]'), (9410420, 'cmp r0, 4'), (9410452, 'ldr r1, [r2, r1, lsl 2]'), (9410912, 'cmp r0, 9'), (9410944, 'ldr r1, [r2, r1, lsl 2]'), (9411320, 'blx r3'), (9411436, 'rsbseq r6, r6, ip, asr r5')],
        calls=[(9410036, 'bl sym.imp.memset'), (9410100, 'blx lr'), (9410200, 'bl sym.imp.objc_enumerationMutation'), (9410280, 'blx ip'), (9410380, 'blx ip'), (9410828, 'blx r3'), (9410864, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9411320, 'blx r3'), (9411356, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9410112, 'beq', 9410404), (9410192, 'beq', 9410204), (9410308, 'blo', 9410156), (9410400, 'bne', 9410156), (9410404, 'b', 9410408), (9410424, 'bge', 9410900), (9410732, 'beq', 9410880), (9410876, 'b', 9410648), (9410880, 'b', 9410884), (9410896, 'b', 9410416), (9410916, 'bge', 9411392), (9411224, 'beq', 9411372), (9411368, 'b', 9411140), (9411372, 'b', 9411376), (9411388, 'b', 9410908)],
        semantics=('setPaused: propagates the paused flag to blockheads and the two dynamic-object family sets. Prologue 0x008f9580 (frame 0x240; base 0x105faf4). Argument: paused byte [sp,0xff] (r2, sxtb per call).\nPass 1: blockheads ivar ffffe4f8 (cell 0x8f9b50) are enumerated (@0x8f95b0); per bh the ffe236f8 call (cell 0x8f9b54) runs with the paused byte (@0x8f96cc-0x8f96ec).\nPass 2: `for i in 0..4` (cmp 4 @0x8f9774) with the SWITCH jump table (cells 0x8f9b64 0xffdeaf18 + 0x8f9b68 0x766360 -> table @ 0x00E4AA0C, dispatch @0x8f9794): the ffffe54c segments (cell 0x8f9b60) are iterated and per node ffe236f8 runs with the paused byte (@0x8f98b0-0x8f990c).\nPass 3: `for i in 0..9` (cmp 9 @0x8f9960) with the second SWITCH jump table (cells 0x8f9b58 0xffdeaf9c + 0x8f9b5c 0x766174 -> table @ 0x00E4AA90, dispatch @0x8f9980): same per-node ffe236f8 propagation (@0x8f9a9c-0x8f9af8). Epilogue 0x8f9b40.\n'),
    ),
    dict(
        name='wtl_saveblockheadinventory',
        method='DynamicWorld -[saveBlockheadInventory:]',
        types='v12@0:4@8',
        start=9143860,
        end=9145216,
        disasm='disasm_worldtileloader_saveblockheadinventory_.txt',
        base_add=9143876,
        base_literal=9145212,
        boundary='ARM.exidx end 0x008b8b80 (listing bound); next ObjC IMP 0x008b8b80 DynamicWorld -[removePortalFromListAtPos:]',
        selectors={
                 0x8b8b18: (15216088, 'dataWithPropertyList:format:options:error:'),
                 0x8b8b20: (15216216, 'saveItemSlotsArray'),
                 0x8b8b2c: (15216196, 'raise:format:'),
                 0x8b8b38: (15216200, 'clientSaveDir'),
                 0x8b8b3c: (15216092, 'setData:forKey:'),
                 0x8b8b48: (15215816, 'stringWithFormat:'),
                 0x8b8b4c: (15216160, 'uniqueID'),
                 0x8b8b60: (15216176, 'gzipDeflate'),
                 0x8b8b64: (15216192, 'sendDataToServer:reliable:'),
                 0x8b8b68: (15216184, 'appendData:'),
                 0x8b8b6c: (15216220, 'appendBytes:length:'),
                 0x8b8b78: (15216180, 'dataWithBytes:length:'),
        },
        imports={
                 0x8b8b14: (17151904, 'objc_msgSend'),
                 0x8b8b24: (16333208, '__CFConstantStringClassReference'),
                 0x8b8b28: (16333272, '__CFConstantStringClassReference'),
                 0x8b8b40: (16333096, '__CFConstantStringClassReference'),
                 0x8b8b58: (16333112, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8b8b34: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8b8b54: (17162240, 'OBJC_IVAR_$_DynamicWorld.worldDatabase', 32),
        },
        classes={
                 0x8b8b1c: (15247824, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x8b8b30: (15247852, 'OBJC_CLASS_$_NSException'),
                 0x8b8b50: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8b8b74: (15247844, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(9143860, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9144020, 'ldr lr, [fp, -0x50]'), (9144088, 'movw r0, 1'), (9144268, 'bl loc.imp.objc_msgSend'), (9144492, 'beq 0x8b89cc'), (9144632, 'blx r6'), (9145212, 'rsbseq r7, sl, r8, lsr 9')],
        calls=[(9143968, 'blx r4'), (9144024, 'blx lr'), (9144224, 'bl loc.imp.objc_msgSend'), (9144268, 'bl loc.imp.objc_msgSend'), (9144292, 'bl loc.imp.objc_msgSend'), (9144340, 'blx ip'), (9144364, 'blx r3'), (9144412, 'blx lr'), (9144472, 'blx r3'), (9144632, 'blx r6'), (9144676, 'bl loc.imp.objc_msgSend'), (9144732, 'bl loc.imp.objc_msgSend'), (9144768, 'blx ip'), (9144904, 'bl loc.imp.objc_msgSend'), (9144956, 'bl loc.imp.objc_msgSend'), (9144992, 'blx ip'), (9145096, 'blx r4')],
        branches=[(9144044, 'beq', 9145008), (9144084, 'beq', 9144420), (9144416, 'b', 9145004), (9144492, 'beq', 9144780), (9144776, 'b', 9145000), (9145000, 'b', 9145004), (9145004, 'b', 9145100)],
        semantics=("saveBlockheadInventory: archives a blockhead's inventory and sends or stores it. Prologue 0x008b8634 (frame 0xe8; base 0x105faf4).\nArchive setup: NSKeyedArchiver (class cell 0x8b8b74 ffe2aef0) with initForWritingWithMutableData (cell 0x8b8b78 ffe23340) and the key **0x21 ('!')** stored at [fp,-0x31] (@0x8b87a8-0x8b87cc); the blockhead's uniqueID (cell 0x8b8b4c ffe2332c) keys the payload.\nClient path: when self.client (ffffe518, cell 0x8b8b34) is non-zero the archive chain (cells ffe2334c/ffe23344/ffe23368/ffe2333c/ffe2af10 @0x8b871c-0x8b885c, including the ffe23344 gzip hook and the ffe2333c finish) sends the payload.\nStore path: otherwise the database write runs with `stringWithFormat:` (ffe231d4 cell 0x8b8b48, NSString ffe2aebc, key 0xfff33e44 cell 0x8b8b58) against worldDatabase (ffffe50c cell 0x8b8b54) via setObject:forKey: (ffe232e8 cell 0x8b8b3c), @0x8b8864-0x8b8948. Gate at the top: the ffe232e4 call + the packed pair (@0x8b865c-0x8b86e8) and the `cmp r0, r1; beq 0x8b8ab0` early exit.\n"),
    ),
    dict(
        name='wtl_teleportblockhead_towo',
        method='DynamicWorld -[teleportBlockhead:toWorkbench:]',
        types='c16@0:4@8@12',
        start=9393752,
        end=9395056,
        disasm='disasm_worldtileloader_teleportblockhead_toworkbench_.txt',
        base_add=9393768,
        base_literal=9395048,
        boundary='ARM.exidx end 0x008f5b70 (listing bound); next ObjC IMP 0x008f5b70 DynamicWorld -[loadNewBlockheadAtPos:craftableItemObject:uniqueID:]',
        selectors={
                 0x8f5b30: (15216012, 'pos'),
                 0x8f5b34: (15217076, 'teleportToPos:'),
                 0x8f5b40: (15217080, 'play'),
                 0x8f5b48: (15216500, 'multiSoundNamed:'),
                 0x8f5b4c: (15216060, 'instance'),
                 0x8f5b64: (15217084, 'addParticleAtPos:velocity:color:gravityType:life:scale:center:'),
        },
        imports={
                 0x8f5b3c: (17151904, 'objc_msgSend'),
                 0x8f5b44: (16333944, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0x8f5b50: (15247876, 'OBJC_CLASS_$_MJSoundManager'),
                 0x8f5b58: (15248020, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(9393752, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9393928, 'strb r0, [fp, -0x39]'), (9394048, 'vstr s0, [sp, 0xa8]'), (9394188, 'cmp r0, 0x100'), (9394296, 'bl method.Vector.Vector_float__float__float__float_'), (9394424, 'bl method.Vector.Vector_float__float__float_'), (9395052, 'andeq r0, r0, r0')],
        calls=[(9393840, 'bl loc.imp.objc_msgSend_stret'), (9393876, 'bl sym.imp.memset'), (9393924, 'bl loc.imp.objc_msgSend'), (9394072, 'blx r6'), (9394092, 'blx r3'), (9394108, 'blx r2'), (9394164, 'bl method.Vector.Vector_float__float__float_'), (9394196, 'bl 0x8ad2a4'), (9394296, 'bl method.Vector.Vector_float__float__float__float_'), (9394332, 'bl loc.imp.objc_msgSend'), (9394340, 'bl 0x8ad2a4'), (9394376, 'bl 0x8ad2a4'), (9394424, 'bl method.Vector.Vector_float__float__float_'), (9394464, 'bl method.Vector.operator_Vector_'), (9394468, 'bl 0x8ad2a4'), (9394512, 'bl 0x8ad2a4'), (9394568, 'bl method.Vector.Vector_float__float__float_'), (9394604, 'bl 0x8ad2a4'), (9394644, 'bl 0x8ad2a4'), (9394940, 'bl loc.imp.objc_msgSend')],
        branches=[(9393824, 'beq', 9393848), (9393844, 'b', 9393880), (9393940, 'beq', 9394964), (9394192, 'bge', 9394960), (9394956, 'b', 9394184), (9394960, 'b', 9394964)],
        semantics=('teleportBlockhead:toWorkbench: teleports a blockhead to a workbench with a randomized landing search. Prologue 0x008f5658 (frame 0x170; base 0x105faf4).\nGate: `[bh pos]` stret getter (ffe23298 cell 0x8f5b30) then the ffe236c0 call (cell 0x8f5b34) sets the BOOL [fp,-0x39]; false exits at 0x8f5b14.\nSound + base point: the MJSoundManager chain (class ffe2af10 cell 0x8f5b50, ffe232c8 cell 0x8f5b4c, ffe23480 cell 0x8f5b48, string 0xfff34184 cell 0x8f5b44) plays with a Vector built from the bh position plus the -5/5 floats (@0x8f5718-0x8f57f4, Vector(float,float,float) ctor).\nLanding search: `for i in 0..0x100 (256)` (cmp 0x100 @0x8f580c): per iteration `bl 0x8ad2a4` (random) divided by the const cell 0x8f5b54 with the double round-trips (d3 = 1.0, cells 0x8f5b20/0x8f5b28) and a Vector4(0.5f, s0, s8, 1.0f) built from the immediates 0x3f000000/0x3f800000 (@0x8f5858-0x8f5878); the class cell 0x8f5b58 (ffe2afa0) + ffe232c8 pair (@0x8f587c-0x8f589c) opens the candidate check, then a second random with the -5 offset and `vadd` doubling (@0x8f58a4-0x8f58f8) builds the next Vector(float,float,float); the loop continues to the placement (tail 0x8f590c+).\nBoundary: the acceptance condition inside the 256-loop (hit test / placement) is recorded as observed from the Vector/random chain.\n'),
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
        'batch': 'DynamicWorld breeding/NPC/service cluster (E27): npcCloseEnoughToBreedWithNPC:, findBreedingPlantNearPlant:, getPlantAtPos:, tooManyNPCsToSpawnMoreNearPos:, setPaused:, saveBlockheadInventory: and teleportBlockhead:toWorkbench:; 7 bodies',
        'claim': ('a static bounded-body map with per-instruction anchors; the wire-format markers, the '
                  'NSLog key strings, the C++ container member layouts and the packet helper at 0x8b84c8 are '
                  'outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'breed_npc.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale breed_npc.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
