#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the SteamTrain riders/fuel cluster: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 2500 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/STEAM_RIDERS.md for the prose and boundaries.
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
    'bl 0xd20620': 0x00d20620,
    'bl 0xd20694': 0x00d20694,
    'bl 0xd20a2c': 0x00d20a2c,
    'bl 0xd20ce0': 0x00d20ce0,
    'bl 0xd2da64': 0x00d2da64,
    'bl 0xd2e3bc': 0x00d2e3bc,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator__Vector2_': 0x004d04b4,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.atan2f': 0x001c410c,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
}

SPECS = [
    dict(
        name='st2_riderbody',
        method='SteamTrain -[riderBodyMatrixForBlockhead:cameraX:]',
        types='(_GLKMatrix4={?=ffffffffffffffff}[16f])16@0:4@8f12',
        start=13823952,
        end=13826220,
        disasm='disasm_worldtileloader_st2_riderbody.txt',
        base_add=13824008,
        base_literal=13826180,
        boundary='ARM.exidx end 0x00d2f8ac (listing bound); next ObjC IMP 0x00d2f8ac SteamTrain -[setTargetVelocity:]',
        selectors={
                 0xd2f88c: (15238616, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0xd2f880: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd2f888: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd2f89c: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xd2f8a4: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xd2f8a8: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
        },
        classes={},
        instructions=[(13823952, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13824068, 'bl method.Vector2.Vector2_float__float_'), (13824176, 'bl sym.imp.__aeabi_idiv'), (13824200, 'ble 0xd2f140'), (13824440, 'bpl 0xd2f22c'), (13826216, 'invalid')],
        calls=[(13824068, 'bl method.Vector2.Vector2_float__float_'), (13824092, 'bl method.Vector2.operator_Vector2_'), (13824100, 'bl method.Vector2.operator_float__'), (13824152, 'bl loc.imp.objc_msgSend'), (13824176, 'bl sym.imp.__aeabi_idiv'), (13824264, 'bl loc.imp.objc_msgSend'), (13824296, 'bl method.Vector2.operator_float__'), (13824344, 'bl method.Vector2.operator_float__'), (13824400, 'bl loc.imp.objc_msgSend'), (13824416, 'bl sym.imp.__aeabi_idiv'), (13824504, 'bl loc.imp.objc_msgSend'), (13824536, 'bl method.Vector2.operator_float__'), (13824568, 'bl method.Vector2.operator_float__'), (13824584, 'bl method.Vector2.operator_float__'), (13824604, 'bl 0xd20620'), (13824716, 'bl method.Vector2.operator__Vector2_'), (13824724, 'bl method.Vector2.operator_float__'), (13824744, 'bl method.Vector2.operator_float__'), (13824756, 'bl sym.imp.atan2f'), (13825088, 'bl 0xd20694'), (13825612, 'bl 0xd2e3bc'), (13826104, 'bl 0xd2da64'), (13826132, 'bl sym.imp.memcpy')],
        branches=[(13824200, 'ble', 13824320), (13824316, 'b', 13824560), (13824440, 'bpl', 13824556), (13824556, 'b', 13824560)],
        semantics=('[[SteamTrain riderBodyMatrixForBlockhead:cameraX:]] (imp 0x00d2efd0, 567w): the rider/render matrix builder - the SAME helper contract as its siblings: `Vector2::Vector2(0, 0.5f)` (`mov lr/r6, 0x3f000000` - the half-offset), `Vector2::operator+`, `Vector2::operator float*()`, the local matrix helper bl 0xd20620 (arg -0.5f = 0xbf000000), the world-macro read via the fffffc8dc chain + `lsl r0, r0, 5` (<<5 = *32) `__aeabi_idiv` macro math, the delta `Vector2::operator-`, **atan2f** (sym.imp.atan2f) for the body angle, then the 14-slot matrix store wall (`str .. [r1, 0..0x34]`). The camera edge clamp follows: `vcmpe; ble` / `bpl` branches (@0xd2f0c8, @0xd2f1b8) pick the clamped branch vs the 5-slot variant (@0xd2f140: `movw r1/r0, 5`).'),
    ),
    dict(
        name='st2_tapradius',
        method='SteamTrain -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=13830092,
        end=13832300,
        disasm='disasm_worldtileloader_st2_tapradius.txt',
        base_add=13830112,
        base_literal=13832296,
        boundary='ARM.exidx end 0x00d3106c (listing bound); next ObjC IMP 0x00d3106c SteamTrain -[isEngine]',
        selectors={
                 0xd31058: (15238616, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0xd31044: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd3104c: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xd31050: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xd31054: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(13830092, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13830220, 'bl method.Vector2.Vector2_float__float_'), (13830424, 'bl sym.imp.atan2f'), (13830652, 'mov r0, sp'), (13832296, 'eorseq pc, r2, ip, lsl 6')],
        calls=[(13830220, 'bl method.Vector2.Vector2_float__float_'), (13830244, 'bl method.Vector2.operator_Vector2_'), (13830252, 'bl method.Vector2.operator_float__'), (13830268, 'bl method.Vector2.operator_float__'), (13830288, 'bl 0xd20620'), (13830384, 'bl method.Vector2.operator__Vector2_'), (13830392, 'bl method.Vector2.operator_float__'), (13830412, 'bl method.Vector2.operator_float__'), (13830424, 'bl sym.imp.atan2f'), (13830756, 'bl 0xd20694'), (13830924, 'bl method.Vector2.operator__Vector2_'), (13831060, 'bl method.Vector2.operator_float__'), (13831076, 'bl method.Vector2.operator_float__'), (13831096, 'bl 0xd20ce0'), (13831332, 'bl 0xd20a2c'), (13831352, 'bl method.Vector2.Vector2_float__float_'), (13831372, 'bl method.Vector2.operator_float__'), (13831388, 'bl method.Vector2.operator_float__'), (13831440, 'bl loc.imp.objc_msgSend'), (13831464, 'bl sym.imp.__aeabi_idiv'), (13831536, 'bl method.Vector2.operator_float__'), (13831552, 'bl method.Vector2.operator_float__'), (13831604, 'bl loc.imp.objc_msgSend'), (13831696, 'bl method.Vector2.operator_float__'), (13831712, 'bl method.Vector2.operator_float__'), (13831764, 'bl loc.imp.objc_msgSend'), (13831780, 'bl sym.imp.__aeabi_idiv'), (13831852, 'bl method.Vector2.operator_float__'), (13831868, 'bl method.Vector2.operator_float__'), (13831920, 'bl loc.imp.objc_msgSend'), (13831984, 'bl method.Vector2.operator_float__'), (13832004, 'bl method.Vector2.operator_float__'), (13832092, 'bl method.Vector2.operator_float__'), (13832128, 'bl method.Vector2.operator_float__'), (13832156, 'bl method.Vector2.operator_float__'), (13832192, 'bl method.Vector2.operator_float__')],
        branches=[(13831488, 'blt', 13831644), (13831640, 'b', 13832032), (13831804, 'bpl', 13831960), (13831956, 'b', 13832024), (13832060, 'bpl', 13832236), (13832084, 'ble', 13832236), (13832148, 'ble', 13832236), (13832220, 'bpl', 13832236), (13832232, 'b', 13832244)],
        semantics=('[[SteamTrain tapIsWithinBodyRadius:]] (imp 0x00d307cc, 552w): the rider/render matrix builder - the SAME helper contract as its siblings: `Vector2::Vector2(0, 0.5f)` (`mov lr/r6, 0x3f000000` - the half-offset), `Vector2::operator+`, `Vector2::operator float*()`, the local matrix helper bl 0xd20620 (arg -0.5f = 0xbf000000), the world-macro read via the fffffc8dc chain + `lsl r0, r0, 5` (<<5 = *32) `__aeabi_idiv` macro math, the delta `Vector2::operator-`, **atan2f** (sym.imp.atan2f) for the body angle, then the 14-slot matrix store wall (`str .. [r1, 0..0x34]`). The tap query reuses the same matrix build; the comparison consumers follow in the listing (36 objc calls).'),
    ),
    dict(
        name='st2_riderpos',
        method='SteamTrain -[riderPosForBlockhead:]',
        types='{Vector=[4f]}12@0:4@8',
        start=13822664,
        end=13823952,
        disasm='disasm_worldtileloader_st2_riderpos.txt',
        base_add=13822704,
        base_literal=13823932,
        boundary='ARM.exidx end 0x00d2efd0 (listing bound); next ObjC IMP 0x00d2efd0 SteamTrain -[riderBodyMatrixForBlockhead:cameraX:]',
        selectors={},
        imports={},
        ivars={
                 0xd2efb8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd2efc0: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xd2efc4: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xd2efc8: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
        },
        classes={},
        instructions=[(13822664, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13822760, 'bl method.Vector2.Vector2_float__float_'), (13822976, 'bl sym.imp.atan2f'), (13823160, 'ldr sl, [sp, 0x14c]'), (13823304, 'bl 0xd20694'), (13823948, 'andeq r0, r0, r0')],
        calls=[(13822760, 'bl method.Vector2.Vector2_float__float_'), (13822784, 'bl method.Vector2.operator_Vector2_'), (13822792, 'bl method.Vector2.operator_float__'), (13822808, 'bl method.Vector2.operator_float__'), (13822840, 'bl 0xd20620'), (13822936, 'bl method.Vector2.operator__Vector2_'), (13822944, 'bl method.Vector2.operator_float__'), (13822964, 'bl method.Vector2.operator_float__'), (13822976, 'bl sym.imp.atan2f'), (13823304, 'bl 0xd20694'), (13823628, 'bl 0xd20ce0'), (13823864, 'bl 0xd20a2c'), (13823896, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[[SteamTrain riderPosForBlockhead:]] (imp 0x00d2eac8, 322w): the rider/render matrix builder - the SAME helper contract as its siblings: `Vector2::Vector2(0, 0.5f)` (`mov lr/r6, 0x3f000000` - the half-offset), `Vector2::operator+`, `Vector2::operator float*()`, the local matrix helper bl 0xd20620 (arg -0.5f = 0xbf000000), the world-macro read via the fffffc8dc chain + `lsl r0, r0, 5` (<<5 = *32) `__aeabi_idiv` macro math, the delta `Vector2::operator-`, **atan2f** (sym.imp.atan2f) for the body angle, then the 14-slot matrix store wall (`str .. [r1, 0..0x34]`). The result feeds the local helper 0xd20694 after the store wall.'),
    ),
    dict(
        name='st2_addfuelitem',
        method='SteamTrain -[addToFuelForItem:]',
        types='v12@0:4i8',
        start=13828144,
        end=13829324,
        disasm='disasm_worldtileloader_st2_addfuelitem.txt',
        base_add=13828160,
        base_literal=13829320,
        boundary='ARM.exidx end 0x00d304cc (listing bound); next ObjC IMP 0x00d304cc SteamTrain -[canDismissFuelUI]',
        selectors={
                 0xd30474: (15238592, 'updateHasFuel'),
                 0xd30480: (15238596, 'instance'),
                 0xd30484: (15238744, 'multiSoundNamed:'),
                 0xd30490: (15238612, 'playAtPosition:'),
                 0xd30498: (15238604, 'isPlaying'),
                 0xd304a0: (15238600, 'soundNamed:'),
                 0xd304a4: (15238608, 'hasFinishedPlaying'),
                 0xd304b8: (15238588, 'isNet'),
                 0xd304c0: (15238772, 'reportAchievementWithIdentifier:'),
        },
        imports={
                 0xd30488: (16441304, '__CFConstantStringClassReference'),
                 0xd30494: (17151904, 'objc_msgSend'),
                 0xd3049c: (16441160, '__CFConstantStringClassReference'),
                 0xd304bc: (16441288, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd30468: (17168312, 'OBJC_IVAR_$_SteamTrain.fuelFraction', 260),
                 0xd30470: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xd3048c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd304a8: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xd304ac: (17168340, 'OBJC_IVAR_$_SteamTrain.sendWhistle', 269),
                 0xd304b0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd304c4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xd3047c: (15251200, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(13828144, 'push {r4, r5, r6, r7, fp, lr}'), (13828180, 'cmp r0, 0xcd'), (13828336, 'blx r2'), (13828580, 'strb r2, [r0]'), (13829320, 'eorseq pc, r2, ip, lsr 21')],
        calls=[(13828292, 'blx r5'), (13828312, 'blx r3'), (13828336, 'blx r2'), (13828392, 'blx r2'), (13828536, 'bl loc.imp.objc_msgSend'), (13828676, 'blx r2'), (13828772, 'blx ip'), (13829048, 'bl loc.imp.objc_msgSend'), (13829072, 'bl loc.imp.objc_msgSend'), (13829096, 'bl loc.imp.objc_msgSend'), (13829160, 'bl method.Vector2.Vector2_float__float_'), (13829188, 'bl loc.imp.objc_msgSend')],
        branches=[(13828188, 'bne', 13828784), (13828348, 'beq', 13828408), (13828404, 'beq', 13828780), (13828612, 'beq', 13828776), (13828688, 'bne', 13828776), (13828776, 'b', 13828780), (13828780, 'b', 13829216), (13828800, 'bne', 13828812), (13828820, 'bne', 13828832), (13828844, 'bne', 13828856), (13828948, 'ble', 13828992)],
        semantics=('[SteamTrain addToFuelForItem:] (imp 0x00d30030, 295w): the ITEM-TYPE GATE `cmp r0, 0xcd` (@0xd30054: **item type 0xcd (205) = the fuel item**); the gate chain (ffe28ad8/ffe28ad4/ffe28ad0/ffe2bc0c calls @0xd30070-0xd300f0 + the ffe28adc sxtb check @0xd30130) accepts the item; the ffffe110 world chain + fffffce0 read then the byte writes (@0xd301d0-0xd301e4: strb x2) store the added fuel; the tail continues with the fuel-count update.\n'),
    ),
    dict(
        name='st2_renderpos',
        method='SteamTrain -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=13821364,
        end=13822520,
        disasm='disasm_worldtileloader_st2_renderpos.txt',
        base_add=13821400,
        base_literal=13822508,
        boundary='ARM.exidx end 0x00d2ea38 (listing bound); next ObjC IMP 0x00d2ea38 SteamTrain -[cameraPosForBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0xd2ea28: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd2ea30: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xd2ea34: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
        },
        classes={},
        instructions=[(13821364, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13821448, 'bl method.Vector2.operator_float__'), (13821624, 'bl sym.imp.atan2f'), (13821780, 'ldr ip, [sp, 0x120]'), (13822516, 'invalid')],
        calls=[(13821448, 'bl method.Vector2.operator_float__'), (13821464, 'bl method.Vector2.operator_float__'), (13821484, 'bl 0xd20620'), (13821584, 'bl method.Vector2.operator__Vector2_'), (13821592, 'bl method.Vector2.operator_float__'), (13821612, 'bl method.Vector2.operator_float__'), (13821624, 'bl sym.imp.atan2f'), (13821952, 'bl 0xd20694'), (13822228, 'bl 0xd20ce0'), (13822464, 'bl 0xd20a2c'), (13822488, 'bl method.Vector2.Vector2_float__float_')],
        branches=[],
        semantics=('[[SteamTrain renderPos]] (imp 0x00d2e5b4, 289w): the rider/render matrix builder - the SAME helper contract as its siblings: `Vector2::Vector2(0, 0.5f)` (`mov lr/r6, 0x3f000000` - the half-offset), `Vector2::operator+`, `Vector2::operator float*()`, the local matrix helper bl 0xd20620 (arg -0.5f = 0xbf000000), the world-macro read via the fffffc8dc chain + `lsl r0, r0, 5` (<<5 = *32) `__aeabi_idiv` macro math, the delta `Vector2::operator-`, **atan2f** (sym.imp.atan2f) for the body angle, then the 14-slot matrix store wall (`str .. [r1, 0..0x34]`). No camera arg: the plain macro read + the same store wall (the render interpolation position).'),
    ),
    dict(
        name='st2_updatehasfuel',
        method='SteamTrain -[updateHasFuel]',
        types='v8@0:4',
        start=13827572,
        end=13828144,
        disasm='disasm_worldtileloader_st2_updatehasfuel.txt',
        base_add=13827588,
        base_literal=13828140,
        boundary='ARM.exidx end 0x00d30030 (listing bound); next ObjC IMP 0x00d30030 SteamTrain -[addToFuelForItem:]',
        selectors={
                 0xd3001c: (15238672, 'objectType'),
                 0xd30020: (15238676, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={},
        ivars={
                 0xd30004: (17168308, 'OBJC_IVAR_$_SteamTrain.hasFuel', 268),
                 0xd3000c: (17168312, 'OBJC_IVAR_$_SteamTrain.fuelFraction', 260),
                 0xd30014: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd30018: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd30028: (17168304, 'OBJC_IVAR_$_SteamTrain.fuelCounter', 264),
        },
        classes={},
        instructions=[(13827572, 'push {fp, lr}'), (13827632, 'beq 0xd2ff1c'), (13827676, 'bpl 0xd2ff1c'), (13827748, 'strb r3, [r0, r1]'), (13828140, 'eorseq pc, r2, r8, ror 25')],
        calls=[(13827824, 'bl loc.imp.objc_msgSend'), (13827860, 'bl loc.imp.objc_msgSend'), (13828048, 'bl loc.imp.objc_msgSend'), (13828084, 'bl loc.imp.objc_msgSend')],
        branches=[(13827632, 'beq', 13827868), (13827676, 'bpl', 13827868), (13827864, 'b', 13828092), (13827900, 'bne', 13828088), (13827940, 'ble', 13828088), (13828088, 'b', 13828092)],
        semantics=('[SteamTrain updateHasFuel] (imp 0x00d2fdf4, 143w): the fuel-state refresh - the **fffffcc0 flag** gate (@0xd2fe24-0xd2fe30) then the float compare `vcmpe; bpl` (@0xd2fe54-0xd2fe5c); on the empty-fuel path the ivars are zeroed: `str r3=0` to the fffffcc4 and fffffcbc cells + `strb 0` to the fffffcc0 flag (@0xd2fe7c-0xd2fea4) and the world-chain tail runs (@0xd2feb0+).\n'),
    ),
    dict(
        name='st2_removerider',
        method='SteamTrain -[removeRider:]',
        types='v12@0:4@8',
        start=13832328,
        end=13832668,
        disasm='disasm_worldtileloader_st2_removerider.txt',
        base_add=13832344,
        base_literal=13832664,
        boundary='ARM.exidx end 0x00d311dc (listing bound); next ObjC IMP 0x00d311dc SteamTrain -[maxNumberOfRiders]',
        selectors={
                 0xd311b8: (15238776, 'removeRider:'),
        },
        imports={
                 0xd311b4: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xd311c0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xd311c4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd311c8: (17168288, 'OBJC_IVAR_$_SteamTrain.rightStationSearchTilePos', 292),
                 0xd311cc: (17168292, 'OBJC_IVAR_$_SteamTrain.leftStationSearchTilePos', 284),
                 0xd311d0: (17168296, 'OBJC_IVAR_$_SteamTrain.serachingForRightStationName', 281),
                 0xd311d4: (17168300, 'OBJC_IVAR_$_SteamTrain.serachingForLeftStationName', 280),
        },
        classes={
                 0xd311bc: (15253264, 'OBJC_CLASS_$_SteamTrain'),
        },
        instructions=[(13832328, 'push {r4, r5, fp, lr}'), (13832456, 'bne 0xd311ac'), (13832488, 'movw ip, 1'), (13832664, 'eorseq lr, r2, r4, asr sl')],
        calls=[(13832420, 'blx lr')],
        branches=[(13832456, 'bne', 13832620)],
        semantics=('[SteamTrain removeRider:] (imp 0x00d31088, 85w): the **ffffcacc sxtb gate** (@0xd31100-0xd31108: non-zero = already removed, exits); otherwise the ffffc89c + fffffcac/b0 ivar chain runs the unlink (@0xd3110c+).\n'),
    ),
    dict(
        name='st2_setneedsremoved',
        method='SteamTrain -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=13829504,
        end=13829840,
        disasm='disasm_worldtileloader_st2_setneedsremoved.txt',
        base_add=13829520,
        base_literal=13829836,
        boundary='ARM.exidx end 0x00d306d0 (listing bound); next ObjC IMP 0x00d306d0 SteamTrain -[setPaused:]',
        selectors={
                 0xd306b4: (15238656, 'setNeedsRemoved:'),
                 0xd306c4: (15238576, 'stop'),
        },
        imports={
                 0xd306b0: (17151900, 'objc_msgSendSuper2'),
                 0xd306c0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd306bc: (17168352, 'OBJC_IVAR_$_SteamTrain.railSound', 248),
                 0xd306c8: (17168356, 'OBJC_IVAR_$_SteamTrain.steamSound', 244),
        },
        classes={
                 0xd306b8: (15253264, 'OBJC_CLASS_$_SteamTrain'),
        },
        instructions=[(13829504, 'push {r4, r5, fp, lr}'), (13829620, 'blx lr'), (13829660, 'ldr lr, [lr, r2]'), (13829836, 'eorseq pc, r2, ip, asr r5')],
        calls=[(13829620, 'blx lr'), (13829712, 'blx r3'), (13829772, 'blx lr')],
        branches=[],
        semantics=("[SteamTrain setNeedsRemoved:] (imp 0x00d30580, 84w): the sxtb'd flag rides the call frame (@0xd305f4 blx) then the **fffffcec/fcf0** ivar chain + the ffe28abc removal call (@0xd305fc-0xd3061c).\n"),
    ),
    dict(
        name='st2_setpaused',
        method='SteamTrain -[setPaused:]',
        types='v12@0:4c8',
        start=13829840,
        end=13830092,
        disasm='disasm_worldtileloader_st2_setpaused.txt',
        base_add=13829856,
        base_literal=13830088,
        boundary='ARM.exidx end 0x00d307cc (listing bound); next ObjC IMP 0x00d307cc SteamTrain -[tapIsWithinBodyRadius:]',
        selectors={
                 0xd307c0: (15238576, 'stop'),
        },
        imports={
                 0xd307bc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd307b8: (17168352, 'OBJC_IVAR_$_SteamTrain.railSound', 248),
                 0xd307c4: (17168356, 'OBJC_IVAR_$_SteamTrain.steamSound', 244),
        },
        classes={},
        instructions=[(13829840, 'push {r4, r5, fp, lr}'), (13829884, 'beq 0xd307b0'), (13829976, 'blx r3'), (13830088, 'eorseq pc, r2, ip, lsl 8')],
        calls=[(13829976, 'blx r3'), (13830036, 'blx lr')],
        branches=[(13829884, 'beq', 13830064)],
        semantics=("[SteamTrain setPaused:] (imp 0x00d306d0, 63w): the sxtb'd pause byte gates (@0xd306f0-0xd306fc: zero exits); the fffffcec/fcf0 + ffe28abc chain propagates the pause (@0xd30700-0xd30770).\n"),
    ),
    dict(
        name='st2_railname',
        method='SteamTrain -[railOrStationNameChanged]',
        types='v8@0:4',
        start=13832696,
        end=13832952,
        disasm='disasm_worldtileloader_st2_railname.txt',
        base_add=13832708,
        base_literal=13832948,
        boundary='ARM.exidx end 0x00d312f8 (listing bound); next ObjC IMP 0x00d312f8 SteamTrain -[needsToUpdateChoiceUI]',
        selectors={},
        imports={},
        ivars={
                 0xd312dc: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xd312e0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd312e4: (17168288, 'OBJC_IVAR_$_SteamTrain.rightStationSearchTilePos', 292),
                 0xd312e8: (17168292, 'OBJC_IVAR_$_SteamTrain.leftStationSearchTilePos', 284),
                 0xd312ec: (17168296, 'OBJC_IVAR_$_SteamTrain.serachingForRightStationName', 281),
                 0xd312f0: (17168300, 'OBJC_IVAR_$_SteamTrain.serachingForLeftStationName', 280),
        },
        classes={},
        instructions=[(13832696, 'push {r4, r5, fp, lr}'), (13832752, 'bne 0xd312d4'), (13832832, 'strb ip, [lr]'), (13832948, 'eorseq lr, r2, r8, ror 17')],
        calls=[],
        branches=[(13832752, 'bne', 13832916)],
        semantics=('[SteamTrain railOrStationNameChanged] (imp 0x00d311f8, 64w): the **ffffcacc gate** (non-zero exits @0xd31228-0xd31230); the fffffcac/b0/b4/b8 chain reads the rail state and **sets the marker bytes** (`movw ip, 1` + `strb ip` x2 @0xd3126c-0xd31280) - the name-changed dirty flag.\n'),
    ),
    dict(
        name='st2_camerapos',
        method='SteamTrain -[cameraPosForBlockhead:]',
        types='{Vector2=[2f]}12@0:4@8',
        start=13822520,
        end=13822664,
        disasm='disasm_worldtileloader_st2_camerapos.txt',
        base_add=13822536,
        base_literal=13822656,
        boundary='ARM.exidx end 0x00d2eac8 (listing bound); next ObjC IMP 0x00d2eac8 SteamTrain -[riderPosForBlockhead:]',
        selectors={
                 0xd2eabc: (15238764, 'renderPos'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(13822520, 'push {r4, sl, fp, lr}'), (13822604, 'bl loc.imp.objc_msgSend_stret'), (13822640, 'bl sym.imp.memset'), (13822660, 'andeq r0, r0, r0')],
        calls=[(13822604, 'bl loc.imp.objc_msgSend_stret'), (13822640, 'bl sym.imp.memset')],
        branches=[(13822588, 'beq', 13822612), (13822608, 'b', 13822644)],
        semantics=('[SteamTrain cameraPosForBlockhead:] (imp 0x00d2ea38, 36w): the struct-returning camera accessor - the stret read on the non-nil path (@0xd2ea8c objc_msgSend_stret) with the 8-byte memset nil-fill (@0xd2eaa4-0xd2eab0); the ffe28b78 chain supplies the receiver.\n'),
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
        'batch': 'SteamTrain riders/fuel cluster (E70): the matrix trio, tapIsWithinBodyRadius:, addToFuelForItem:, updateHasFuel, removeRider:, setNeedsRemoved:, setPaused:, railOrStationNameChanged and cameraPosForBlockhead:; 11 bodies',
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
                        default=NATIVE / 'steam_riders.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale steam_riders.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
