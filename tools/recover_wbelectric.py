#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the Workbench electricity system: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 1699 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORKBENCH_ELECTRICITY.md for the prose and boundaries.
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
    'bl 0x11ff19c': 0x011ff19c,
    'bl 0x11ff69c': 0x011ff69c,
    'bl 0xae3538': 0x00ae3538,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl sym.imp.__wrap_powf': 0x001c3f98,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_': 0x00a197b4,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsAirOrSnow_Tile_': 0x00a12760,
    'bl sym.tileIsTree_Tile_': 0x00a13214,
}

SPECS = [
    dict(
        name='wb_avaiablelec',
        method='Workbench -[availableElectricity]',
        types='S8@0:4',
        start=11539076,
        end=11539136,
        disasm='disasm_worldtileloader_wb_avaiablelec.txt',
        base_add=11539084,
        base_literal=11539132,
        boundary='ARM.exidx end 0x00b012c0 (listing bound); next ObjC IMP 0x00b012c0 Workbench -[conductsElectricity]',
        selectors={},
        imports={},
        ivars={
                 0xb012b8: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
        },
        classes={},
        instructions=[(11539076, 'sub sp, sp, 8'), (11539116, 'ldrh r0, [r0]'), (11539132, 'subseq lr, r5, r0, ror 16')],
        calls=[],
        branches=[],
        semantics=('[Workbench availableElectricity] (imp 0x00b01284, 58w): **halfword read** (ldrh) of the electricity store through the **fffff150** cell - the stored charge is a **u16**.\n'),
    ),
    dict(
        name='wb_conductelec',
        method='Workbench -[conductsElectricity]',
        types='c8@0:4',
        start=11539136,
        end=11539324,
        disasm='disasm_worldtileloader_wb_conductelec.txt',
        base_add=11539152,
        base_literal=11539320,
        boundary='ARM.exidx end 0x00b0137c (listing bound); next ObjC IMP 0x00b0137c Workbench -[subtractElectricty:]',
        selectors={
                 0xb01370: (15229284, 'isStorageDevice'),
                 0xb01374: (15229288, 'generatesElectricity'),
        },
        imports={
                 0xb0136c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11539136, 'push {fp, lr}'), (11539220, 'bne 0xb01358'), (11539280, 'movne r0, 1'), (11539320, 'subseq lr, r5, ip, lsl r8')],
        calls=[(11539200, 'blx ip'), (11539264, 'blx r2')],
        branches=[(11539220, 'bne', 11539288)],
        semantics=('[Workbench conductsElectricity] (imp 0x00b012c0, 47w): the delegate cascade - the ffe26670 call (`blx ip; sxtb; cmp; bne` @0xb01300-0xb01314) falls through to the ffe26674 call; either returning true marks conductivity (`movne 1` @0xb01350).\n'),
    ),
    dict(
        name='wb_subtractelec',
        method='Workbench -[subtractElectricty:]',
        types='c12@0:4S8',
        start=11539324,
        end=11540304,
        disasm='disasm_worldtileloader_wb_subtractelec.txt',
        base_add=11539340,
        base_literal=11540300,
        boundary='ARM.exidx end 0x00b01750 (listing bound); next ObjC IMP 0x00b01750 Workbench -[actionTitle]',
        selectors={
                 0xb01724: (15228872, 'objectType'),
                 0xb01728: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xb0173c: (15229088, 'updateHasFuel'),
        },
        imports={
                 0xb01738: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb01710: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xb01718: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xb0171c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb01720: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb0172c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb01730: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xb01734: (17165468, 'OBJC_IVAR_$_Workbench.particleCreateTimerSteamEngine', 280),
        },
        classes={},
        instructions=[(11539324, 'push {r4, r5, r6, sl, fp, lr}'), (11539364, 'strh r2, [fp, -0x1a]'), (11539400, 'bgt 0xb01484'), (11539444, 'strh r0, [r1]'), (11539452, 'strb r0, [fp, -0x1b]'), (11540300, 'subseq lr, r5, r0, ror 14')],
        calls=[(11539548, 'bl loc.imp.objc_msgSend'), (11539584, 'bl loc.imp.objc_msgSend'), (11540140, 'bl loc.imp.objc_msgSend'), (11540176, 'bl loc.imp.objc_msgSend'), (11540220, 'blx ip')],
        branches=[(11539400, 'bgt', 11539588), (11539620, 'bne', 11540228), (11539660, 'ble', 11540224), (11539696, 'bge', 11540224), (11539700, 'b', 11539704), (11539748, 'ble', 11539796), (11539804, 'beq', 11539920), (11539916, 'b', 11539704), (11539968, 'ble', 11540012), (11540224, 'b', 11540228)],
        semantics=('[Workbench subtractElectricty:] (imp 0x00b0137c, 245w): **the electricity drain**: the amount is kept as a halfword on the stack (`strh r2, [fp,-0x1a]` @0xb013a4); the guard compares stored vs requested (`cmp r0, r1; bgt` @0xb013c0-0xb013c8: not enough exits); the subtraction **`sub r0, r2, r0; strh r0, [r1]`** (@0xb013f0-0xb013f4) writes back the u16 store; the dirty byte is set (`strb r0=1` @0xb013fc) and the flag cells **ffffc8d8/c8b4/c89c** propagate through the ffe264d4/d8 notifies - the workbench reports its own electricity change (the distribution-grid edge).\n'),
    ),
    dict(
        name='wb_genelectric',
        method='Workbench -[generatesElectricity]',
        types='c8@0:4',
        start=11541540,
        end=11542208,
        disasm='disasm_worldtileloader_wb_genelectric.txt',
        base_add=11541548,
        base_literal=11541672,
        boundary='ARM.exidx end 0x00b01ec0 (listing bound); next ObjC IMP 0x00b01cac Workbench -[usesStoresConductsOrProducesElectricity]',
        selectors={},
        imports={},
        ivars={
                 0xb01ca4: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb01eb8: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11541540, 'sub sp, sp, 0x10'), (11541600, 'beq 0xb01c90'), (11541632, 'cmp r0, 0x14'), (11542204, 'subseq sp, r5, r8, lsr lr')],
        calls=[],
        branches=[(11541600, 'beq', 11541648), (11541736, 'beq', 11542180), (11541780, 'beq', 11542180), (11541824, 'beq', 11542180), (11541868, 'beq', 11542180), (11541912, 'beq', 11542180), (11541956, 'beq', 11542180), (11542000, 'beq', 11542180), (11542044, 'beq', 11542180), (11542088, 'beq', 11542180), (11542132, 'beq', 11542180)],
        semantics=('[Workbench generatesElectricity] (imp 0x00b01c24, 167w): **workbench type == 0xf (15) or 0x14 (20) → 1** (@0xb01c54/0xb01c80): the generating types (the solar/furnace family).\n'),
    ),
    dict(
        name='wb_useselectric',
        method='Workbench -[usesStoresConductsOrProducesElectricity]',
        types='c8@0:4',
        start=11541676,
        end=11542208,
        disasm='disasm_worldtileloader_wb_useselectric.txt',
        base_add=11541684,
        base_literal=11542204,
        boundary='ARM.exidx end 0x00b01ec0 (listing bound); next ObjC IMP 0x00b01ec0 Workbench -[energyFraction]',
        selectors={},
        imports={},
        ivars={
                 0xb01eb8: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11541676, 'sub sp, sp, 0x10'), (11541724, 'cmp r0, 0xf'), (11541824, 'beq 0xb01ea4'), (11541956, 'beq 0xb01ea4'), (11542204, 'subseq sp, r5, r8, lsr lr')],
        calls=[],
        branches=[(11541736, 'beq', 11542180), (11541780, 'beq', 11542180), (11541824, 'beq', 11542180), (11541868, 'beq', 11542180), (11541912, 'beq', 11542180), (11541956, 'beq', 11542180), (11542000, 'beq', 11542180), (11542044, 'beq', 11542180), (11542088, 'beq', 11542180), (11542132, 'beq', 11542180)],
        semantics=('[Workbench usesStoresConductsOrProducesElectricity] (imp 0x00b01cac, 133w): the **workbench-type enumeration** - a 9-compare chain over the type cell (fffff120): exits true for **0xf (15), 0x14 (20), 0x15 (21), 0x11 (17), 0x10 (16), 0x1b (27), ...** (@0xb01cdc-0xb01dc4): the set of workbench variants wired to the electricity system.\n'),
    ),
    dict(
        name='wb_energyfrac',
        method='Workbench -[energyFraction]',
        types='f8@0:4',
        start=11542208,
        end=11542624,
        disasm='disasm_worldtileloader_wb_energyfrac.txt',
        base_add=11542224,
        base_literal=11542620,
        boundary='ARM.exidx end 0x00b02060 (listing bound); next ObjC IMP 0x00b02060 Workbench -[setPaused:]',
        selectors={
                 0xb02058: (15229096, 'combinedLightForSolarPanel'),
        },
        imports={
                 0xb02054: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb02040: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb0204c: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
        },
        classes={},
        instructions=[(11542208, 'push {fp, lr}'), (11542268, 'bne 0xb01fc0'), (11542500, 'movw r0, 0x2000'), (11542544, 'vdiv.f32 s0, s2, s0'), (11542620, 'subseq sp, r5, ip, lsl ip')],
        calls=[(11542320, 'blx r2')],
        branches=[(11542268, 'bne', 11542464), (11542348, 'bpl', 11542368), (11542412, 'bpl', 11542432), (11542428, 'b', 11542440), (11542460, 'b', 11542576), (11542496, 'bne', 11542560), (11542556, 'b', 11542576)],
        semantics=('[Workbench energyFraction] (imp 0x00b01ec0, 104w): the per-type fraction: type **0x14 (20)** reads the live level via the ffe265b4 call and clamps it (`vcmpe; bpl` + the f64 compare and guard @0xb01f44-0xb01fa8); type **0x15 (21)** computes **stored / 0x2000** - `movw r0, 0x2000` (**8192 = the capacity constant**) + `vcvt.f32.u32; vdiv.f32` (@0xb01fe4-0xb02010); other types return 0.\n'),
    ),
    dict(
        name='wb_solarlight_full',
        method='Workbench -[combinedLightForSolarPanelWithFullSunlight]',
        types='f8@0:4',
        start=11461128,
        end=11461896,
        disasm='disasm_worldtileloader_wb_solarlight_full.txt',
        base_add=11461144,
        base_literal=11461888,
        boundary='ARM.exidx end 0x00aee508 (listing bound); next ObjC IMP 0x00aee508 Workbench -[combinedLightForSolarPanel]',
        selectors={
                 0xaee4f0: (15228680, 'macroTiles'),
        },
        imports={
                 0xaee4ec: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xaee4e8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaee4f4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(11461128, 'push {r4, sl, fp, lr}'), (11461320, 'bl sym.tileIsAirOrSnow_Tile_'), (11461428, 'bl sym.imp.__wrap_powf'), (11461512, 'vcmpe.f32 s0, s2'), (11461892, 'andeq r0, r0, r0')],
        calls=[(11461264, 'blx ip'), (11461308, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11461320, 'bl sym.tileIsAirOrSnow_Tile_'), (11461428, 'bl sym.imp.__wrap_powf'), (11461772, 'bl sym.tileIsTree_Tile_'), (11461856, 'bl 0x11ff19c')],
        branches=[(11461332, 'beq', 11461824), (11461348, 'beq', 11461824), (11461524, 'bpl', 11461540), (11461536, 'b', 11461548), (11461604, 'bpl', 11461620), (11461616, 'b', 11461628), (11461684, 'bpl', 11461700), (11461696, 'b', 11461716), (11461784, 'beq', 11461812), (11461820, 'b', 11461840)],
        semantics=("[Workbench combinedLightForSolarPanelWithFullSunlight] (imp 0x00aee208, 192w): the solar calc - the position walk (ffffc8a0/c89c) + `tileAtWorldPosition` (@0xaee2bc) then **`tileIsAirOrSnow`** (@0xaee2c8: snow blocks the panel!) + the tile byte [r0+3] == **0x2e ('.')** check (@0xaee2e0); the falloff uses **`__wrap_powf`** (@0xaee334!) over the height fraction (`vcvt.f32.u32; vdiv.f32`); the sunlight triplet comes from the halfwords [r1+0xe] + [r2+0x10] + [r2+0x12] (three sun levels summed @0xaee34c-0xaee364) and is compared against the threshold (`vcmpe.f32` @0xaee388).\n"),
    ),
    dict(
        name='wb_solarlight',
        method='Workbench -[combinedLightForSolarPanel]',
        types='f8@0:4',
        start=11461896,
        end=11463192,
        disasm='disasm_worldtileloader_wb_solarlight.txt',
        base_add=11461912,
        base_literal=11463184,
        boundary='ARM.exidx end 0x00aeea18 (listing bound); next ObjC IMP 0x00aeea18 Workbench -[update:accurateDT:isSimulation:]',
        selectors={
                 0xaee9f0: (15228680, 'macroTiles'),
                 0xaeea00: (15229076, 'getDayNightFractionForX:atWorldTime:'),
                 0xaeea04: (15228756, 'worldTime'),
                 0xaeea0c: (15229080, 'getWeatherFractionForPos:'),
        },
        imports={
                 0xaee9ec: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xaee9e8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaee9f4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(11461896, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11463188, 'andeq r0, r0, r0')],
        calls=[(11462036, 'blx ip'), (11462080, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11462092, 'bl sym.tileIsAirOrSnow_Tile_'), (11462200, 'bl sym.imp.__wrap_powf'), (11462428, 'blx r2'), (11462468, 'blx r3'), (11462668, 'bl loc.imp.objc_msgSend'), (11463036, 'bl sym.tileIsTree_Tile_'), (11463136, 'bl 0x11ff69c')],
        branches=[(11462104, 'beq', 11463088), (11462120, 'beq', 11463088), (11462544, 'bpl', 11462560), (11462556, 'b', 11462568), (11462696, 'ble', 11462828), (11462736, 'bpl', 11462756), (11462752, 'b', 11462764), (11462868, 'bpl', 11462884), (11462880, 'b', 11462892), (11462948, 'bpl', 11462964), (11462960, 'b', 11462980), (11463048, 'beq', 11463076), (11463084, 'b', 11463104)],
        semantics=('[Workbench combinedLightForSolarPanel] (imp 0x00aee508, 324w): the non-full-sunlight variant - the same position/sun walk with its own branch arms (4 objc calls + tile probes; the ffe26414 family + ffffc8a0/c89c cells); the full-sun sibling supplies the power curve.\n'),
    ),
    dict(
        name='wb_getlightrgb',
        method='Workbench -[getLightRGB]',
        types='{Vector=[4f]}8@0:4',
        start=11418732,
        end=11419492,
        disasm='disasm_worldtileloader_wb_getlightrgb.txt',
        base_add=11418748,
        base_literal=11419488,
        boundary='ARM.exidx end 0x00ae3f64 (listing bound); next ObjC IMP 0x00ae3f64 Workbench -[updatePortalLight]',
        selectors={},
        imports={},
        ivars={
                 0xae3f54: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xae3f58: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xae3f5c: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
        },
        classes={},
        instructions=[(11418732, 'push {r4, sl, fp, lr}'), (11418892, 'movw r0, 0x30'), (11418956, 'movw r0, 4'), (11419488, 'subseq fp, r7, r0, ror lr')],
        calls=[(11418840, 'bl 0xae3538'), (11419460, 'bl method.Vector.Vector_float__float__float_')],
        branches=[(11418852, 'beq', 11418988), (11418888, 'beq', 11418920), (11418916, 'b', 11418984), (11418952, 'bne', 11418980), (11418980, 'b', 11418984), (11418984, 'b', 11419408), (11419020, 'beq', 11419060), (11419056, 'bne', 11419404), (11419116, 'bne', 11419144), (11419140, 'b', 11419400), (11419176, 'bne', 11419204), (11419200, 'b', 11419396), (11419236, 'bne', 11419264), (11419260, 'b', 11419392), (11419296, 'bne', 11419328), (11419324, 'b', 11419388), (11419360, 'bne', 11419384), (11419384, 'b', 11419388), (11419388, 'b', 11419392), (11419392, 'b', 11419396), (11419396, 'b', 11419400), (11419400, 'b', 11419404), (11419404, 'b', 11419408)],
        semantics=('[Workbench getLightRGB] (imp 0x00ae3c6c, 190w): the light-color table - the fffff144 flag arm returns **(0x30, 0x82, 0xdc) = (48, 130, 220)** (the electric blue-cyan glow @0xae3d0c); type **3** returns (4, 0x32, 0x40) (@0xae3d4c); further type arms continue the workbench color set (the switch over the type cell fffff120 after the helper 0xae3538 gate).\n'),
    ),
    dict(
        name='wb_portallight',
        method='Workbench -[updatePortalLight]',
        types='v8@0:4',
        start=11419492,
        end=11420352,
        disasm='disasm_worldtileloader_wb_portallight.txt',
        base_add=11419508,
        base_literal=11420348,
        boundary='ARM.exidx end 0x00ae42c0 (listing bound); next ObjC IMP 0x00ae42c0 Workbench -[initWithWorld:dynamicWorld:atPosition:cache:type:flipped:saveDict:placedByClient:clientName:]',
        selectors={
                 0xae4280: (15228708, 'getLightRGB'),
                 0xae428c: (15228704, 'release'),
                 0xae4290: (15228700, 'removeFromMacroBlock'),
                 0xae4294: (15228696, 'removeFromTiles'),
                 0xae42a0: (15228712, 'alloc'),
                 0xae42b4: (15228716, 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'),
                 0xae42b8: (15228680, 'macroTiles'),
        },
        imports={
                 0xae4288: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xae4284: (17165372, 'OBJC_IVAR_$_Workbench.light', 100),
                 0xae42a4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xae42a8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xae42ac: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xae42b0: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
        },
        classes={
                 0xae4298: (15249616, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11419492, 'push {r4, r5, r6, r7, fp, lr}'), (11419796, 'bl sym.imp.memset'), (11419840, 'ldr r2, [0x00ae42a4]'), (11420348, 'subseq fp, r7, r8, ror fp')],
        calls=[(11419616, 'blx r4'), (11419652, 'blx r3'), (11419688, 'blx r3'), (11419760, 'bl loc.imp.objc_msgSend_stret'), (11419796, 'bl sym.imp.memset'), (11419832, 'bl loc.imp.objc_msgSend'), (11419948, 'bl sym.makeIntpair_int__int_'), (11419996, 'bl method.Vector.operator_float__'), (11420016, 'bl method.Vector.operator_float__'), (11420036, 'bl method.Vector.operator_float__'), (11420152, 'bl loc.imp.objc_msgSend'), (11420232, 'bl loc.imp.objc_msgSend'), (11420276, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(11419744, 'beq', 11419768), (11419764, 'b', 11419800)],
        semantics=('[Workbench updatePortalLight] (imp 0x00ae3f64, 215w): the portal light refresh - the fffff148 cell chain + the ffe26424/28/2c/30 objc family; the stret read with the **0x10 (16)-byte memset** nil-fill (@0xae407c-0xae4094); the ffffc8a0 tail walks the portal position.\n'),
    ),
    dict(
        name='wb_storagedev',
        method='Workbench -[isStorageDevice]',
        types='c8@0:4',
        start=11541460,
        end=11541540,
        disasm='disasm_worldtileloader_wb_storagedev.txt',
        base_add=11541468,
        base_literal=11541536,
        boundary='ARM.exidx end 0x00b01c24 (listing bound); next ObjC IMP 0x00b01c24 Workbench -[generatesElectricity]',
        selectors={},
        imports={},
        ivars={
                 0xb01c1c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11541460, 'sub sp, sp, 8'), (11541504, 'cmp r0, 0x15'), (11541536, 'subseq sp, r5, r0, lsl pc')],
        calls=[],
        branches=[],
        semantics=('[Workbench isStorageDevice] (imp 0x00b01bd4, 20w): **type == 0x15 (21) → 1** (@0xb01c00): type 21 = the battery/storage workbench (the type whose energyFraction is stored/8192).\n'),
    ),
    dict(
        name='wb_conductelec',
        method='Workbench -[conductsElectricity]',
        types='c8@0:4',
        start=11539136,
        end=11539324,
        disasm='disasm_worldtileloader_wb_conductelec.txt',
        base_add=11539152,
        base_literal=11539320,
        boundary='ARM.exidx end 0x00b0137c (listing bound); next ObjC IMP 0x00b0137c Workbench -[subtractElectricty:]',
        selectors={
                 0xb01370: (15229284, 'isStorageDevice'),
                 0xb01374: (15229288, 'generatesElectricity'),
        },
        imports={
                 0xb0136c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11539136, 'push {fp, lr}'), (11539220, 'bne 0xb01358'), (11539280, 'movne r0, 1'), (11539320, 'subseq lr, r5, ip, lsl r8')],
        calls=[(11539200, 'blx ip'), (11539264, 'blx r2')],
        branches=[(11539220, 'bne', 11539288)],
        semantics=('[Workbench conductsElectricity] (imp 0x00b012c0, 47w): the delegate cascade - the ffe26670 call (`blx ip; sxtb; cmp; bne` @0xb01300-0xb01314) falls through to the ffe26674 call; either returning true marks conductivity (`movne 1` @0xb01350).\n'),
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
        'batch': 'Workbench electricity sub-cluster (E75): the store/drain, the type tables (generate/use/storage), energyFraction 8192, the solar panels and the portal/light colors; 12 bodies',
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
                        default=NATIVE / 'workbench_electricity.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale workbench_electricity.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
