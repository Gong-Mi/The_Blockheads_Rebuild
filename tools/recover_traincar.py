#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line closes: the TrainCar, the consist vehicle: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 7219 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/TRAIN_CAR.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.Vector2.Vector2__': 0x004d5170,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
}

SPECS = [
    dict(
        name='tc_00',
        method='TrainCar -[loadDerivedStuff]',
        types='v8@0:4',
        start=10712400,
        end=10716664,
        disasm='disasm_worldtileloader_tc_00.txt',
        base_add=10712416,
        base_literal=10716464,
        boundary='ARM.exidx end 0x00a385f8 (listing bound); next ObjC IMP 0x00a385f8 TrainCar -[objectType]',
        selectors={
                 0xa38554: (15224260, 'arrayWithObjects:'),
                 0xa38580: (15224264, 'shaderNamed:attributes:uniforms:'),
                 0xa38598: (15224268, 'textureNamed:'),
                 0xa385ac: (15224272, 'textureNamed:withAlpha:'),
                 0xa385d0: (15224276, 'getRailAtPos:'),
                 0xa385d4: (15224280, 'currentConfiguration'),
        },
        imports={
                 0xa38558: (16347576, '__CFConstantStringClassReference'),
                 0xa3855c: (16347544, '__CFConstantStringClassReference'),
                 0xa38560: (16347560, '__CFConstantStringClassReference'),
                 0xa38564: (16347688, '__CFConstantStringClassReference'),
                 0xa38568: (16347672, '__CFConstantStringClassReference'),
                 0xa3856c: (16347656, '__CFConstantStringClassReference'),
                 0xa38570: (16347640, '__CFConstantStringClassReference'),
                 0xa38574: (16347624, '__CFConstantStringClassReference'),
                 0xa38578: (16347592, '__CFConstantStringClassReference'),
                 0xa3857c: (16347608, '__CFConstantStringClassReference'),
                 0xa38584: (16347528, '__CFConstantStringClassReference'),
                 0xa3858c: (16347720, '__CFConstantStringClassReference'),
                 0xa38590: (16347704, '__CFConstantStringClassReference'),
                 0xa3859c: (16347736, '__CFConstantStringClassReference'),
                 0xa385a4: (16347752, '__CFConstantStringClassReference'),
                 0xa385b0: (16347768, '__CFConstantStringClassReference'),
                 0xa385b4: (16347784, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa38534: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa38538: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa3853c: (17161240, 'OBJC_IVAR_$_TrainCar.rightWheelVel', 120),
                 0xa38540: (17161236, 'OBJC_IVAR_$_TrainCar.leftWheelVel', 112),
                 0xa38544: (17161264, 'OBJC_IVAR_$_TrainCar.visualVelocity', 128),
                 0xa38548: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xa38588: (17161272, 'OBJC_IVAR_$_TrainCar.shader', 56),
                 0xa38594: (17161284, 'OBJC_IVAR_$_TrainCar.worldObjectShader', 60),
                 0xa385a0: (17161276, 'OBJC_IVAR_$_TrainCar.tileTexture', 64),
                 0xa385a8: (17161288, 'OBJC_IVAR_$_TrainCar.itemTexture', 72),
                 0xa385b8: (17161280, 'OBJC_IVAR_$_TrainCar.tileDestructTexture', 68),
                 0xa385bc: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xa385c0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa385c4: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xa385c8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0xa38550: (15249044, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(10712400, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10716660, 'strhteq r7, [r2], -0xf0')],
        calls=[(10712564, 'bl loc.imp.objc_msgSend'), (10712700, 'bl loc.imp.objc_msgSend'), (10712748, 'bl loc.imp.objc_msgSend'), (10712836, 'bl loc.imp.objc_msgSend'), (10712900, 'bl loc.imp.objc_msgSend'), (10712940, 'bl loc.imp.objc_msgSend'), (10713008, 'bl loc.imp.objc_msgSend'), (10713068, 'bl loc.imp.objc_msgSend'), (10713136, 'bl loc.imp.objc_msgSend'), (10713244, 'bl method.Vector2.Vector2_float__float_'), (10713264, 'bl method.Vector2.operator_Vector2_'), (10713360, 'bl method.Vector2.Vector2_float__float_'), (10713380, 'bl method.Vector2.operator_Vector2_'), (10713512, 'bl method.Vector2.Vector2_float__float_'), (10713656, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10713788, 'bl loc.imp.objc_msgSend'), (10713832, 'bl loc.imp.objc_msgSend'), (10713984, 'bl method.Vector2.Vector2_float__float_'), (10714004, 'bl method.Vector2.operator_Vector2_'), (10714104, 'bl method.Vector2.Vector2_float__float_'), (10714124, 'bl method.Vector2.operator_Vector2_'), (10714220, 'bl method.Vector2.Vector2_float__float_'), (10714240, 'bl method.Vector2.operator_Vector2_'), (10714348, 'bl method.Vector2.Vector2_float__float_'), (10714368, 'bl method.Vector2.operator_Vector2_'), (10714472, 'bl method.Vector2.Vector2_float__float_'), (10714492, 'bl method.Vector2.operator_Vector2_'), (10714588, 'bl method.Vector2.Vector2_float__float_'), (10714608, 'bl method.Vector2.operator_Vector2_'), (10714712, 'bl method.Vector2.Vector2_float__float_'), (10714732, 'bl method.Vector2.operator_Vector2_'), (10714832, 'bl method.Vector2.Vector2_float__float_'), (10714852, 'bl method.Vector2.operator_Vector2_'), (10714952, 'bl method.Vector2.Vector2_float__float_'), (10714972, 'bl method.Vector2.operator_Vector2_'), (10715072, 'bl method.Vector2.Vector2_float__float_'), (10715092, 'bl method.Vector2.operator_Vector2_'), (10715192, 'bl method.Vector2.Vector2_float__float_'), (10715212, 'bl method.Vector2.operator_Vector2_'), (10715312, 'bl method.Vector2.Vector2_float__float_'), (10715332, 'bl method.Vector2.operator_Vector2_'), (10715436, 'bl method.Vector2.Vector2_float__float_'), (10715456, 'bl method.Vector2.operator_Vector2_'), (10715556, 'bl method.Vector2.Vector2_float__float_'), (10715576, 'bl method.Vector2.operator_Vector2_'), (10715672, 'bl method.Vector2.Vector2_float__float_'), (10715692, 'bl method.Vector2.operator_Vector2_'), (10715796, 'bl method.Vector2.Vector2_float__float_'), (10715816, 'bl method.Vector2.operator_Vector2_'), (10715920, 'bl method.Vector2.Vector2_float__float_'), (10715940, 'bl method.Vector2.operator_Vector2_'), (10716036, 'bl method.Vector2.Vector2_float__float_'), (10716056, 'bl method.Vector2.operator_Vector2_'), (10716156, 'bl method.Vector2.Vector2_float__float_'), (10716176, 'bl method.Vector2.operator_Vector2_'), (10716280, 'bl method.Vector2.Vector2_float__float_'), (10716300, 'bl method.Vector2.operator_Vector2_'), (10716396, 'bl method.Vector2.Vector2_float__float_'), (10716416, 'bl method.Vector2.operator_Vector2_')],
        branches=[(10713676, 'beq', 10716456), (10713692, 'bne', 10716456), (10713808, 'beq', 10716452), (10713852, 'bhi', 10716444), (10714264, 'b', 10716448), (10714632, 'b', 10716448), (10714996, 'b', 10716448), (10715356, 'b', 10716448), (10715716, 'b', 10716448), (10716080, 'b', 10716448), (10716440, 'b', 10716448), (10716444, 'b', 10716448), (10716448, 'b', 10716452), (10716452, 'b', 10716456)],
        semantics=('[TrainCar loadDerivedStuff] (imp 0x00a37550, 1066w): the car geometry - **Vector2(float,float) x24 + operator+(Vector2) x23** (the consist offsets!) + objc x11 + the consts 0xbf00 (-0.5f)/0x3f00 (0.5f)/0x3e80 (0.25f)/0x3f40 (0.75f) (the wheel/car placement units) + tileAtWorldPositionLoaded.\n'),
    ),
    dict(
        name='tc_01',
        method='TrainCar -[objectType]',
        types='i8@0:4',
        start=10716664,
        end=10716692,
        disasm='disasm_worldtileloader_tc_01.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a38614 (listing bound); next ObjC IMP 0x00a38614 TrainCar -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10716664, 'sub sp, sp, 8'), (10716688, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar objectType] (imp 0x00a385f8, 7w): the object-type constant.\n'),
    ),
    dict(
        name='tc_02',
        method='TrainCar -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:]',
        types='@36@0:4@8@12{?=ii}16@24@28@32',
        start=10716692,
        end=10717484,
        disasm='disasm_worldtileloader_tc_02.txt',
        base_add=10716708,
        base_literal=10717480,
        boundary='ARM.exidx end 0x00a3892c (listing bound); next ObjC IMP 0x00a3892c TrainCar -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xa38904: (15224284, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0xa38918: (15224292, 'objectForKey:'),
                 0xa38920: (15224288, 'retain'),
                 0xa38924: (15224296, 'loadDerivedStuff'),
        },
        imports={
                 0xa38910: (16347800, '__CFConstantStringClassReference'),
                 0xa38914: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa38908: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa3890c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa3891c: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xa388fc: (15253028, 'OBJC_CLASS_$_TrainCar'),
        },
        instructions=[(10716692, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10717480, 'rsbeq r7, r2, r8, asr 9')],
        calls=[(10716884, 'bl loc.imp.objc_msgSendSuper2'), (10716988, 'bl method.Vector2.operator_float__'), (10717068, 'bl method.Vector2.operator_float__'), (10717140, 'blx r2'), (10717228, 'blx r3'), (10717328, 'blx lr'), (10717344, 'blx r2'), (10717412, 'blx r2')],
        branches=[(10716912, 'bne', 10716928), (10716924, 'b', 10717424), (10717092, 'beq', 10717168), (10717164, 'b', 10717372), (10717240, 'beq', 10717368), (10717368, 'b', 10717372)],
        semantics=('[TrainCar initWithWorld:...placedByClient:...] (imp 0x00a38614, 198w): the placed ctor.\n'),
    ),
    dict(
        name='tc_03',
        method='TrainCar -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=10718936,
        end=10719436,
        disasm='disasm_worldtileloader_tc_03.txt',
        base_add=10718952,
        base_literal=10719432,
        boundary='ARM.exidx end 0x00a390cc (listing bound); next ObjC IMP 0x00a390cc TrainCar -[blockheadsLoaded]',
        selectors={
                 0xa390ac: (15224320, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0xa390b8: (15224324, 'remoteUpdate:'),
                 0xa390c4: (15224296, 'loadDerivedStuff'),
        },
        imports={
                 0xa390a8: (17151900, 'objc_msgSendSuper2'),
                 0xa390b4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa390bc: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa390c0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0xa390b0: (15253028, 'OBJC_CLASS_$_TrainCar'),
        },
        instructions=[(10718936, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10719432, 'rsbeq r6, r2, r4, lsl 24')],
        calls=[(10719088, 'blx r6'), (10719188, 'blx r3'), (10719240, 'bl method.Vector2.operator_float__'), (10719320, 'bl method.Vector2.operator_float__'), (10719376, 'blx r3')],
        branches=[(10719116, 'bne', 10719132), (10719128, 'b', 10719388)],
        semantics=('[TrainCar initWithWorld:dynamicWorld:cache:netData:] (imp 0x00a38ed8, 125w): the netData ctor.\n'),
    ),
    dict(
        name='tc_04',
        method='TrainCar -[blockheadsLoaded]',
        types='v8@0:4',
        start=10719436,
        end=10720432,
        disasm='disasm_worldtileloader_tc_04.txt',
        base_add=10719452,
        base_literal=10720428,
        boundary='ARM.exidx end 0x00a394b0 (listing bound); next ObjC IMP 0x00a394b0 TrainCar -[getSaveDict]',
        selectors={
                 0xa39464: (15224304, 'maxNumberOfRiders'),
                 0xa39470: (15224328, 'blockheads'),
                 0xa39478: (15224332, 'count'),
                 0xa39488: (15224336, 'autorelease'),
                 0xa3948c: (15224340, 'objectAtIndex:'),
                 0xa39490: (15224288, 'retain'),
                 0xa39494: (15224344, 'isClientBlockheadBeingControlledByServer'),
                 0xa3949c: (15224352, 'setRidingObject:'),
                 0xa394a8: (15224348, 'stopRiding'),
        },
        imports={
                 0xa39460: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa39468: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa39474: (17164452, 'OBJC_IVAR_$_TrainCar.savedBlockheadIndex', 84),
                 0xa39480: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
        },
        classes={},
        instructions=[(10719436, 'push {r4, r5, fp, lr}'), (10720428, 'rsbeq r6, r2, r0, lsl sl')],
        calls=[(10719528, 'blx r2'), (10719600, 'bl loc.imp.objc_msgSend'), (10719744, 'blx r2'), (10719828, 'bl loc.imp.objc_msgSend'), (10719888, 'bl loc.imp.objc_msgSend'), (10719904, 'bl loc.imp.objc_msgSend'), (10720052, 'blx r2'), (10720144, 'bl loc.imp.objc_msgSend'), (10720184, 'bl loc.imp.objc_msgSend'), (10720320, 'blx ip')],
        branches=[(10719540, 'bge', 10720344), (10719648, 'blt', 10719936), (10719756, 'bhs', 10719936), (10720064, 'beq', 10720228), (10720224, 'b', 10720324), (10720324, 'b', 10720328), (10720340, 'b', 10719480)],
        semantics=('[TrainCar blockheadsLoaded] (imp 0x00a390cc, 249w): the blockheads-loaded sweep.\n'),
    ),
    dict(
        name='tc_05',
        method='TrainCar -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=10722660,
        end=10722736,
        disasm='disasm_worldtileloader_tc_05.txt',
        base_add=10722676,
        base_literal=10722732,
        boundary='ARM.exidx end 0x00a39db0 (listing bound); next ObjC IMP 0x00a39db0 TrainCar -[trainCarCreationNetData]',
        selectors={
                 0xa39da8: (15224356, 'getSaveDict'),
        },
        imports={
                 0xa39da4: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(10722660, 'push {fp, lr}'), (10722732, 'rsbeq r5, r2, r8, ror sp')],
        calls=[(10722712, 'blx r3')],
        branches=[],
        semantics=('[TrainCar freeBlockCreationSaveDict] (imp 0x00a39d64, 19w): the freeblock save dict.\n'),
    ),
    dict(
        name='tc_06',
        method='TrainCar -[trainCarCreationNetData]',
        types='{TrainCarCreationNetData={DynamicObjectNetData=QIIC[7C]}QQQQQfffffffffC[3C]}8@0:4',
        start=10722736,
        end=10723948,
        disasm='disasm_worldtileloader_tc_06.txt',
        base_add=10722752,
        base_literal=10723944,
        boundary='ARM.exidx end 0x00a3a26c (listing bound); next ObjC IMP 0x00a3a26c TrainCar -[creationNetDataForClient:]',
        selectors={
                 0xa3a224: (15224384, 'dynamicObjectNetData'),
                 0xa3a230: (15224376, 'uniqueID'),
        },
        imports={},
        ivars={
                 0xa3a228: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xa3a238: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
                 0xa3a240: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xa3a248: (17161208, 'OBJC_IVAR_$_TrainCar.engineCar', 176),
                 0xa3a250: (17161260, 'OBJC_IVAR_$_TrainCar.engineIsRight', 180),
                 0xa3a254: (17161264, 'OBJC_IVAR_$_TrainCar.visualVelocity', 128),
                 0xa3a258: (17161240, 'OBJC_IVAR_$_TrainCar.rightWheelVel', 120),
                 0xa3a25c: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xa3a260: (17161236, 'OBJC_IVAR_$_TrainCar.leftWheelVel', 112),
                 0xa3a264: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
        },
        classes={},
        instructions=[(10722736, 'push {r4, r5, r6, r7, fp, lr}'), (10723944, 'rsbeq r5, r2, ip, lsr 26')],
        calls=[(10722820, 'bl loc.imp.objc_msgSend_stret'), (10722856, 'bl sym.imp.memset'), (10723008, 'bl loc.imp.objc_msgSend'), (10723104, 'bl loc.imp.objc_msgSend'), (10723212, 'bl loc.imp.objc_msgSend'), (10723320, 'bl loc.imp.objc_msgSend'), (10723428, 'bl loc.imp.objc_msgSend'), (10723468, 'bl method.Vector2.operator_float__'), (10723512, 'bl method.Vector2.operator_float__'), (10723556, 'bl method.Vector2.operator_float__'), (10723600, 'bl method.Vector2.operator_float__'), (10723644, 'bl method.Vector2.operator_float__'), (10723688, 'bl method.Vector2.operator_float__'), (10723732, 'bl method.Vector2.operator_float__'), (10723776, 'bl method.Vector2.operator_float__'), (10723820, 'bl method.Vector2.operator_float__')],
        branches=[(10722804, 'beq', 10722828), (10722824, 'b', 10722860), (10722968, 'beq', 10723024), (10723060, 'beq', 10723120), (10723172, 'beq', 10723228), (10723280, 'beq', 10723336), (10723388, 'beq', 10723444)],
        semantics=('[TrainCar trainCarCreationNetData] (imp 0x00a39db0, 303w): the creation record.\n'),
    ),
    dict(
        name='tc_07',
        method='TrainCar -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=10723948,
        end=10724256,
        disasm='disasm_worldtileloader_tc_07.txt',
        base_add=10723964,
        base_literal=10724168,
        boundary='ARM.exidx end 0x00a3a3a0 (listing bound); next ObjC IMP 0x00a3a34c TrainCar -[updateNetDataForClient:]',
        selectors={
                 0xa3a338: (15224388, 'trainCarCreationNetData'),
                 0xa3a340: (15224392, 'dataWithBytes:length:'),
                 0xa3a398: (15224396, 'creationNetDataForClient:'),
        },
        imports={
                 0xa3a33c: (17151904, 'objc_msgSend'),
                 0xa3a394: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xa3a344: (15249056, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(10723948, 'push {fp, lr}'), (10724252, 'mlseq r2, r0, r7, r5')],
        calls=[(10724032, 'bl loc.imp.objc_msgSend_stret'), (10724068, 'bl sym.imp.memset'), (10724132, 'blx ip'), (10724232, 'blx ip')],
        branches=[(10724016, 'beq', 10724040), (10724036, 'b', 10724072)],
        semantics=('[TrainCar creationNetDataForClient:] (imp 0x00a3a26c, 56w): the creation record.\n'),
    ),
    dict(
        name='tc_08',
        method='TrainCar -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=10724172,
        end=10724256,
        disasm='disasm_worldtileloader_tc_08.txt',
        base_add=10724188,
        base_literal=10724252,
        boundary='ARM.exidx end 0x00a3a3a0 (listing bound); next ObjC IMP 0x00a3a3a0 TrainCar -[dealloc]',
        selectors={
                 0xa3a398: (15224396, 'creationNetDataForClient:'),
        },
        imports={
                 0xa3a394: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(10724172, 'push {fp, lr}'), (10724252, 'mlseq r2, r0, r7, r5')],
        calls=[(10724232, 'blx ip')],
        branches=[],
        semantics=('[TrainCar updateNetDataForClient:] (imp 0x00a3a34c, 21w): the net update.\n'),
    ),
    dict(
        name='tc_09',
        method='TrainCar -[dealloc]',
        types='v8@0:4',
        start=10724256,
        end=10724824,
        disasm='disasm_worldtileloader_tc_09.txt',
        base_add=10724272,
        base_literal=10724820,
        boundary='ARM.exidx end 0x00a3a5d8 (listing bound); next ObjC IMP 0x00a3a5d8 TrainCar -[remoteUpdate:]',
        selectors={
                 0xa3a5a8: (15224400, 'release'),
                 0xa3a5b0: (15224336, 'autorelease'),
                 0xa3a5bc: (15224304, 'maxNumberOfRiders'),
                 0xa3a5c4: (15224404, 'dealloc'),
        },
        imports={
                 0xa3a5a4: (17151904, 'objc_msgSend'),
                 0xa3a5c0: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xa3a5ac: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xa3a5b4: (17161256, 'OBJC_IVAR_$_TrainCar.rightWheelRail', 204),
                 0xa3a5b8: (17161252, 'OBJC_IVAR_$_TrainCar.leftWheelRail', 200),
                 0xa3a5cc: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
        },
        classes={
                 0xa3a5c8: (15253028, 'OBJC_CLASS_$_TrainCar'),
        },
        instructions=[(10724256, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10724820, 'rsbeq r5, r2, ip, lsr r7')],
        calls=[(10724392, 'blx ip'), (10724440, 'blx ip'), (10724488, 'blx ip'), (10724552, 'blx r2'), (10724640, 'bl loc.imp.objc_msgSend'), (10724760, 'blx r3')],
        branches=[(10724564, 'bge', 10724696), (10724692, 'b', 10724504)],
        semantics=('[TrainCar dealloc] (imp 0x00a3a3a0, 142w): the teardown.\n'),
    ),
    dict(
        name='tc_10',
        method='TrainCar -[remoteUpdate:]',
        types='v12@0:4@8',
        start=10724824,
        end=10731836,
        disasm='disasm_worldtileloader_tc_10.txt',
        base_add=10724840,
        base_literal=10728920,
        boundary='ARM.exidx end 0x00a3c13c (listing bound); next ObjC IMP 0x00a3c13c TrainCar -[blockheadCanRide:usingItem:]',
        selectors={
                 0xa3b5e0: (15224324, 'remoteUpdate:'),
                 0xa3b5f0: (15224412, 'isClient'),
                 0xa3b5f8: (15224408, 'getBytes:length:'),
                 0xa3b704: (15224304, 'maxNumberOfRiders'),
                 0xa3b730: (15224416, 'isNet'),
                 0xa3b73c: (15224376, 'uniqueID'),
                 0xa3b744: (15224348, 'stopRiding'),
                 0xa3b748: (15224336, 'autorelease'),
                 0xa3b75c: (15224360, 'countByEnumeratingWithState:objects:count:'),
                 0xa3b760: (15224420, 'allBlockheadsIncludingNet'),
                 0xa3bb54: (15224288, 'retain'),
                 0xa3bb60: (15224424, 'objectType'),
                 0xa3bb64: (15224428, 'dynamicWorldChangedAtPos:objectType:'),
                 0xa3c068: (15224412, 'isClient'),
                 0xa3c070: (15224304, 'maxNumberOfRiders'),
                 0xa3c078: (15224416, 'isNet'),
                 0xa3c07c: (15224376, 'uniqueID'),
                 0xa3c080: (15224348, 'stopRiding'),
                 0xa3c084: (15224336, 'autorelease'),
                 0xa3c08c: (15224360, 'countByEnumeratingWithState:objects:count:'),
                 0xa3c090: (15224420, 'allBlockheadsIncludingNet'),
                 0xa3c094: (15224288, 'retain'),
                 0xa3c09c: (15224424, 'objectType'),
                 0xa3c0a0: (15224428, 'dynamicWorldChangedAtPos:objectType:'),
                 0xa3c0cc: (15224400, 'release'),
                 0xa3c0d8: (15224432, 'trainCarWithID:'),
        },
        imports={
                 0xa3b5dc: (17151900, 'objc_msgSendSuper2'),
                 0xa3b5ec: (17151904, 'objc_msgSend'),
                 0xa3c064: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3b5e8: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xa3b5f4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa3b728: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xa3b74c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa3bb5c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa3c06c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa3c074: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xa3c088: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa3c098: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa3c0a4: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa3c0a8: (17161264, 'OBJC_IVAR_$_TrainCar.visualVelocity', 128),
                 0xa3c0ac: (17161240, 'OBJC_IVAR_$_TrainCar.rightWheelVel', 120),
                 0xa3c0b0: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xa3c0b4: (17161236, 'OBJC_IVAR_$_TrainCar.leftWheelVel', 112),
                 0xa3c0b8: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xa3c0bc: (17161260, 'OBJC_IVAR_$_TrainCar.engineIsRight', 180),
                 0xa3c0c4: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
                 0xa3c0d0: (17161224, 'OBJC_IVAR_$_TrainCar.remoteRightCarID', 152),
                 0xa3c0e8: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xa3c0f0: (17161228, 'OBJC_IVAR_$_TrainCar.remoteLeftCarID', 144),
                 0xa3c104: (17161208, 'OBJC_IVAR_$_TrainCar.engineCar', 176),
                 0xa3c10c: (17161232, 'OBJC_IVAR_$_TrainCar.remoteEngineCarID', 160),
        },
        classes={
                 0xa3b5e4: (15253028, 'OBJC_CLASS_$_TrainCar'),
        },
        instructions=[(10724824, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10731832, 'invalid')],
        calls=[(10724916, 'blx lr'), (10725044, 'blx lr'), (10725080, 'blx r3'), (10725156, 'blx r2'), (10725384, 'blx r2'), (10725492, 'bl loc.imp.objc_msgSend'), (10725604, 'bl loc.imp.objc_msgSend'), (10725644, 'bl loc.imp.objc_msgSend'), (10725872, 'bl loc.imp.objc_msgSend'), (10726028, 'blx r2'), (10726052, 'bl sym.imp.memset'), (10726100, 'blx lr'), (10726200, 'bl sym.imp.objc_enumerationMutation'), (10726272, 'blx r2'), (10726308, 'bl loc.imp.objc_msgSend'), (10726448, 'bl loc.imp.objc_msgSend'), (10726508, 'bl loc.imp.objc_msgSend'), (10726572, 'blx ip'), (10726700, 'bl loc.imp.objc_msgSend'), (10726736, 'bl loc.imp.objc_msgSend'), (10726844, 'blx ip'), (10727016, 'bl loc.imp.objc_msgSend'), (10727056, 'bl loc.imp.objc_msgSend'), (10727188, 'blx r2'), (10727416, 'blx r2'), (10727524, 'bl loc.imp.objc_msgSend'), (10727636, 'bl loc.imp.objc_msgSend'), (10727676, 'bl loc.imp.objc_msgSend'), (10727860, 'blx r2'), (10727884, 'bl sym.imp.memset'), (10727932, 'blx lr'), (10728032, 'bl sym.imp.objc_enumerationMutation'), (10728104, 'blx r2'), (10728140, 'bl loc.imp.objc_msgSend'), (10728280, 'bl loc.imp.objc_msgSend'), (10728312, 'bl loc.imp.objc_msgSend'), (10728376, 'blx ip'), (10728504, 'bl loc.imp.objc_msgSend'), (10728540, 'bl loc.imp.objc_msgSend'), (10728644, 'blx ip'), (10728812, 'bl loc.imp.objc_msgSend'), (10728852, 'bl loc.imp.objc_msgSend'), (10729032, 'blx r2'), (10729192, 'blx r2'), (10729416, 'bl method.Vector2.operator_float__'), (10729460, 'bl method.Vector2.operator_float__'), (10729504, 'bl method.Vector2.operator_float__'), (10729548, 'bl method.Vector2.operator_float__'), (10729592, 'bl method.Vector2.operator_float__'), (10729636, 'bl method.Vector2.operator_float__'), (10729680, 'bl method.Vector2.operator_float__'), (10729724, 'bl method.Vector2.operator_float__'), (10729768, 'bl method.Vector2.operator_float__'), (10729972, 'bl loc.imp.objc_msgSend'), (10730116, 'bl loc.imp.objc_msgSend'), (10730160, 'bl loc.imp.objc_msgSend'), (10730176, 'blx r2'), (10730392, 'bl loc.imp.objc_msgSend'), (10730568, 'bl loc.imp.objc_msgSend'), (10730712, 'bl loc.imp.objc_msgSend'), (10730756, 'bl loc.imp.objc_msgSend'), (10730772, 'blx r2'), (10730972, 'bl loc.imp.objc_msgSend'), (10731148, 'bl loc.imp.objc_msgSend'), (10731292, 'bl loc.imp.objc_msgSend'), (10731336, 'bl loc.imp.objc_msgSend'), (10731352, 'blx r2'), (10731548, 'bl loc.imp.objc_msgSend')],
        branches=[(10724952, 'bne', 10731608), (10725092, 'bne', 10727128), (10725168, 'bge', 10727124), (10725180, 'bne', 10725204), (10725200, 'b', 10725224), (10725220, 'b', 10725224), (10725296, 'beq', 10725688), (10725396, 'bne', 10725688), (10725416, 'beq', 10725684), (10725420, 'b', 10725424), (10725520, 'beq', 10725684), (10725524, 'b', 10725528), (10725684, 'b', 10727104), (10725736, 'beq', 10726880), (10725740, 'b', 10725744), (10725800, 'beq', 10725912), (10725900, 'bne', 10725912), (10725904, 'b', 10725908), (10725908, 'b', 10726876), (10726112, 'beq', 10726868), (10726192, 'beq', 10726204), (10726284, 'beq', 10726744), (10726336, 'bne', 10726744), (10726340, 'b', 10726344), (10726584, 'bne', 10726620), (10726740, 'b', 10726872), (10726744, 'b', 10726748), (10726772, 'blo', 10726156), (10726864, 'bne', 10726156), (10726868, 'b', 10726872), (10726872, 'b', 10726876), (10726876, 'b', 10727100), (10726936, 'beq', 10727096), (10727096, 'b', 10727100), (10727100, 'b', 10727104), (10727104, 'b', 10727108), (10727120, 'b', 10725108), (10727124, 'b', 10728960), (10727200, 'bge', 10728956), (10727212, 'bne', 10727236), (10727232, 'b', 10727256), (10727252, 'b', 10727256), (10727328, 'beq', 10727720), (10727428, 'bne', 10727720), (10727448, 'beq', 10727716), (10727452, 'b', 10727456), (10727552, 'beq', 10727716), (10727556, 'b', 10727560), (10727716, 'b', 10728900), (10727736, 'beq', 10728676), (10727740, 'b', 10727744), (10727944, 'beq', 10728668), (10728024, 'beq', 10728036), (10728116, 'beq', 10728544), (10728168, 'bne', 10728544), (10728172, 'b', 10728176), (10728388, 'bne', 10728424), (10728544, 'b', 10728548), (10728572, 'blo', 10727988), (10728664, 'bne', 10727988), (10728668, 'b', 10728672), (10728672, 'b', 10728896), (10728732, 'beq', 10728892), (10728892, 'b', 10728896), (10728896, 'b', 10728900), (10728900, 'b', 10728904), (10728916, 'b', 10727140), (10728956, 'b', 10728960), (10729044, 'bge', 10729316), (10729104, 'beq', 10729236), (10729204, 'beq', 10729224), (10729216, 'b', 10729232), (10729232, 'b', 10729236), (10729236, 'b', 10729240), (10729252, 'b', 10728984), (10729328, 'bne', 10729780), (10729344, 'bne', 10729384), (10729380, 'beq', 10729780), (10729812, 'beq', 10731604), (10729864, 'beq', 10730344), (10729868, 'b', 10729872), (10729908, 'beq', 10730008), (10730000, 'beq', 10730312), (10730004, 'b', 10730008), (10730224, 'bne', 10730272), (10730268, 'b', 10730308), (10730308, 'b', 10730312), (10730312, 'b', 10730444), (10730460, 'beq', 10730924), (10730464, 'b', 10730468), (10730504, 'beq', 10730604), (10730596, 'beq', 10730908), (10730600, 'b', 10730604), (10730820, 'bne', 10730868), (10730864, 'b', 10730904), (10730904, 'b', 10730908), (10730908, 'b', 10731024), (10731040, 'beq', 10731500), (10731044, 'b', 10731048), (10731084, 'beq', 10731184), (10731176, 'beq', 10731492), (10731180, 'b', 10731184), (10731400, 'bne', 10731452), (10731444, 'b', 10731488), (10731488, 'b', 10731492), (10731492, 'b', 10731600), (10731600, 'b', 10731604), (10731604, 'b', 10731608)],
        semantics=('[TrainCar remoteUpdate:] (imp 0x00a3a5d8, 1753w): the giant net update - objc x33 + **fast enumeration x2** (`objc_enumerationMutation`) + memset x2 + float* x9 + consts 0x10/0x20: the car state syncs across the consist.\n'),
    ),
    dict(
        name='tc_11',
        method='TrainCar -[blockheadCanRide:usingItem:]',
        types='c16@0:4@8i12',
        start=10731836,
        end=10732132,
        disasm='disasm_worldtileloader_tc_11.txt',
        base_add=10731852,
        base_literal=10732128,
        boundary='ARM.exidx end 0x00a3c264 (listing bound); next ObjC IMP 0x00a3c264 TrainCar -[updatePosition:]',
        selectors={
                 0xa3c254: (15224304, 'maxNumberOfRiders'),
        },
        imports={
                 0xa3c250: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3c24c: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xa3c258: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
        },
        classes={},
        instructions=[(10731836, 'push {fp, lr}'), (10732128, 'rsbeq r3, r2, r0, lsr 19')],
        calls=[(10731980, 'blx r2')],
        branches=[(10731904, 'beq', 10731920), (10731916, 'b', 10732096), (10731992, 'bge', 10732088), (10732052, 'bne', 10732068), (10732064, 'b', 10732096), (10732068, 'b', 10732072), (10732084, 'b', 10731932)],
        semantics=('[TrainCar blockheadCanRide:usingItem:] (imp 0x00a3c13c, 74w): the ride gate.\n'),
    ),
    dict(
        name='tc_12',
        method='TrainCar -[updatePosition:]',
        types='v16@0:4{?=ii}8',
        start=10732132,
        end=10732680,
        disasm='disasm_worldtileloader_tc_12.txt',
        base_add=10732148,
        base_literal=10732676,
        boundary='ARM.exidx end 0x00a3c488 (listing bound); next ObjC IMP 0x00a3c488 TrainCar -[update:accurateDT:isSimulation:]',
        selectors={
                 0xa3c45c: (15224304, 'maxNumberOfRiders'),
                 0xa3c468: (15224440, 'updatePosition:'),
                 0xa3c474: (15224416, 'isNet'),
                 0xa3c47c: (15224436, 'markCircumNavigateX:'),
        },
        imports={
                 0xa3c458: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3c454: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa3c46c: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xa3c480: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xa3c460: (15253028, 'OBJC_CLASS_$_TrainCar'),
        },
        instructions=[(10732132, 'push {r4, r5, fp, lr}'), (10732676, 'rsbeq r3, r2, r8, ror r8')],
        calls=[(10732268, 'blx r2'), (10732428, 'blx r2'), (10732512, 'blx r3'), (10732616, 'bl loc.imp.objc_msgSendSuper2')],
        branches=[(10732204, 'beq', 10732540), (10732280, 'bge', 10732536), (10732340, 'beq', 10732516), (10732440, 'bne', 10732516), (10732516, 'b', 10732520), (10732532, 'b', 10732220), (10732536, 'b', 10732540)],
        semantics=('[TrainCar updatePosition:] (imp 0x00a3c264, 137w): the position update.\n'),
    ),
    dict(
        name='tc_13',
        method='TrainCar -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=10732680,
        end=10734148,
        disasm='disasm_worldtileloader_tc_13.txt',
        base_add=10732696,
        base_literal=10734144,
        boundary='ARM.exidx end 0x00a3ca44 (listing bound); next ObjC IMP 0x00a3ca44 TrainCar -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0xa3c9ec: (15224288, 'retain'),
                 0xa3c9f0: (15224432, 'trainCarWithID:'),
                 0xa3ca30: (15224444, 'isEngine'),
        },
        imports={
                 0xa3c9e8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3c9dc: (17161228, 'OBJC_IVAR_$_TrainCar.remoteLeftCarID', 144),
                 0xa3c9e4: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xa3c9f4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa3c9fc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa3ca00: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa3ca0c: (17161224, 'OBJC_IVAR_$_TrainCar.remoteRightCarID', 152),
                 0xa3ca14: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
                 0xa3ca24: (17161232, 'OBJC_IVAR_$_TrainCar.remoteEngineCarID', 160),
                 0xa3ca2c: (17161208, 'OBJC_IVAR_$_TrainCar.engineCar', 176),
        },
        classes={},
        instructions=[(10732680, 'push {r4, r5, r6, r7, fp, lr}'), (10734144, 'rsbeq r3, r2, r4, asr r6')],
        calls=[(10732944, 'bl loc.imp.objc_msgSend'), (10732960, 'blx r2'), (10733128, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10733388, 'bl loc.imp.objc_msgSend'), (10733404, 'blx r2'), (10733572, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10733752, 'blx r2'), (10733888, 'bl loc.imp.objc_msgSend'), (10733904, 'blx r2')],
        branches=[(10732776, 'beq', 10733180), (10732780, 'b', 10732784), (10732820, 'bne', 10733140), (10733008, 'beq', 10733052), (10733048, 'b', 10733136), (10733136, 'b', 10733176), (10733176, 'b', 10733180), (10733220, 'beq', 10733624), (10733224, 'b', 10733228), (10733264, 'bne', 10733584), (10733452, 'beq', 10733496), (10733492, 'b', 10733580), (10733580, 'b', 10733620), (10733620, 'b', 10733624), (10733664, 'beq', 10734036), (10733668, 'b', 10733672), (10733708, 'bne', 10733996), (10733764, 'bne', 10733996), (10733952, 'beq', 10733992), (10733992, 'b', 10734032), (10734032, 'b', 10734036)],
        semantics=('[TrainCar update:accurateDT:isSimulation:] (imp 0x00a3c488, 367w): the tick - objc x3 + tileAtWorldPositionLoaded x2.\n'),
    ),
    dict(
        name='tc_14',
        method='TrainCar -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=10734148,
        end=10734700,
        disasm='disasm_worldtileloader_tc_14.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3cc6c (listing bound); next ObjC IMP 0x00a3cc6c TrainCar -[maxHealth]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10734148, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10734696, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        calls=[],
        branches=[],
        semantics=('[TrainCar draw:...] (imp 0x00a3ca44, 138w): the car draw (the shared render path).\n'),
    ),
    dict(
        name='tc_15',
        method='TrainCar -[maxHealth]',
        types='S8@0:4',
        start=10734700,
        end=10734728,
        disasm='disasm_worldtileloader_tc_15.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3cc88 (listing bound); next ObjC IMP 0x00a3cc88 TrainCar -[renderPos]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10734700, 'sub sp, sp, 8'), (10734724, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar maxHealth] (imp 0x00a3cc6c, 7w): the health cap.\n'),
    ),
    dict(
        name='tc_16',
        method='TrainCar -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=10734728,
        end=10734968,
        disasm='disasm_worldtileloader_tc_16.txt',
        base_add=10734760,
        base_literal=10734844,
        boundary='ARM.exidx end 0x00a3cd78 (listing bound); next ObjC IMP 0x00a3cd00 TrainCar -[riderPosForBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0xa3ccf8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(10734728, 'push {fp, lr}'), (10734964, 'strhteq r2, [r2], -0xd4')],
        calls=[(10734808, 'bl method.Vector2.Vector2_float__float_'), (10734828, 'bl method.Vector2.operator_Vector2_'), (10734872, 'bl method.Vector.Vector__'), (10734948, 'bl sym.imp.memcpy')],
        branches=[],
        semantics=('[TrainCar renderPos] (imp 0x00a3cc88, 30w): the render position.\n'),
    ),
    dict(
        name='tc_17',
        method='TrainCar -[riderPosForBlockhead:]',
        types='{Vector=[4f]}12@0:4@8',
        start=10734848,
        end=10734968,
        disasm='disasm_worldtileloader_tc_17.txt',
        base_add=10734904,
        base_literal=10734964,
        boundary='ARM.exidx end 0x00a3cd78 (listing bound); next ObjC IMP 0x00a3cd28 TrainCar -[riderBodyMatrixForBlockhead:cameraX:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10734848, 'push {fp, lr}'), (10734964, 'strhteq r2, [r2], -0xd4')],
        calls=[(10734872, 'bl method.Vector.Vector__'), (10734948, 'bl sym.imp.memcpy')],
        branches=[],
        semantics=('[TrainCar riderPosForBlockhead:] (imp 0x00a3cd00, 10w): the rider position.\n'),
    ),
    dict(
        name='tc_18',
        method='TrainCar -[riderBodyMatrixForBlockhead:cameraX:]',
        types='(_GLKMatrix4={?=ffffffffffffffff}[16f])16@0:4@8f12',
        start=10734888,
        end=10734968,
        disasm='disasm_worldtileloader_tc_18.txt',
        base_add=10734904,
        base_literal=10734964,
        boundary='ARM.exidx end 0x00a3cd78 (listing bound); next ObjC IMP 0x00a3cd78 TrainCar -[setTargetVelocity:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10734888, 'push {fp, lr}'), (10734964, 'strhteq r2, [r2], -0xd4')],
        calls=[(10734948, 'bl sym.imp.memcpy')],
        branches=[],
        semantics=('[TrainCar riderBodyMatrixForBlockhead:cameraX:] (imp 0x00a3cd28, 20w): the rider matrix.\n'),
    ),
    dict(
        name='tc_19',
        method='TrainCar -[setTargetVelocity:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=10734968,
        end=10734996,
        disasm='disasm_worldtileloader_tc_19.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3cd94 (listing bound); next ObjC IMP 0x00a3cd94 TrainCar -[riderDPadShouldGiveDiscreteValues]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10734968, 'sub sp, sp, 0x10'), (10734992, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar setTargetVelocity:] (imp 0x00a3cd78, 7w): the velocity setter (constant).\n'),
    ),
    dict(
        name='tc_20',
        method='TrainCar -[riderDPadShouldGiveDiscreteValues]',
        types='c8@0:4',
        start=10734996,
        end=10735024,
        disasm='disasm_worldtileloader_tc_20.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3cdb0 (listing bound); next ObjC IMP 0x00a3cdb0 TrainCar -[addRider:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10734996, 'sub sp, sp, 8'), (10735020, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar riderDPadShouldGiveDiscreteValues] (imp 0x00a3cd94, 7w): returns **0**.\n'),
    ),
    dict(
        name='tc_21',
        method='TrainCar -[addRider:]',
        types='v12@0:4@8',
        start=10735024,
        end=10736516,
        disasm='disasm_worldtileloader_tc_21.txt',
        base_add=10735040,
        base_literal=10736512,
        boundary='ARM.exidx end 0x00a3d384 (listing bound); next ObjC IMP 0x00a3d384 TrainCar -[removeRider:]',
        selectors={
                 0xa3d328: (15224344, 'isClientBlockheadBeingControlledByServer'),
                 0xa3d32c: (15224304, 'maxNumberOfRiders'),
                 0xa3d330: (15224412, 'isClient'),
                 0xa3d338: (15224288, 'retain'),
                 0xa3d348: (15224416, 'isNet'),
                 0xa3d35c: (15224424, 'objectType'),
                 0xa3d360: (15224428, 'dynamicWorldChangedAtPos:objectType:'),
                 0xa3d36c: (15224348, 'stopRiding'),
                 0xa3d378: (15224336, 'autorelease'),
        },
        imports={
                 0xa3d324: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3d334: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa3d340: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xa3d350: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa3d358: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(10735024, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10736512, 'rsbeq r2, r2, ip, lsr 26')],
        calls=[(10735084, 'blx ip'), (10735152, 'blx r3'), (10735216, 'blx r2'), (10735400, 'bl loc.imp.objc_msgSend'), (10735480, 'blx r4'), (10735608, 'bl loc.imp.objc_msgSend'), (10735644, 'bl loc.imp.objc_msgSend'), (10735740, 'blx r2'), (10736012, 'bl loc.imp.objc_msgSend'), (10736084, 'blx r3'), (10736244, 'blx r2'), (10736372, 'bl loc.imp.objc_msgSend'), (10736408, 'bl loc.imp.objc_msgSend')],
        branches=[(10735096, 'beq', 10735672), (10735228, 'bge', 10735668), (10735288, 'bne', 10735648), (10735492, 'bne', 10735528), (10735648, 'b', 10735652), (10735664, 'b', 10735168), (10735668, 'b', 10736412), (10735752, 'bge', 10735924), (10735812, 'bne', 10735820), (10735816, 'b', 10736412), (10735876, 'bne', 10735900), (10735888, 'bne', 10735900), (10735900, 'b', 10735904), (10735904, 'b', 10735908), (10735920, 'b', 10735692), (10735932, 'beq', 10736412), (10736096, 'beq', 10736260), (10736156, 'beq', 10736292), (10736256, 'bne', 10736292)],
        semantics=('[TrainCar addRider:] (imp 0x00a3cdb0, 373w): the rider attach.\n'),
    ),
    dict(
        name='tc_22',
        method='TrainCar -[removeRider:]',
        types='v12@0:4@8',
        start=10736516,
        end=10737132,
        disasm='disasm_worldtileloader_tc_22.txt',
        base_add=10736532,
        base_literal=10737128,
        boundary='ARM.exidx end 0x00a3d5ec (listing bound); next ObjC IMP 0x00a3d5ec TrainCar -[swipeUpGesture]',
        selectors={
                 0xa3d5b8: (15224304, 'maxNumberOfRiders'),
                 0xa3d5c4: (15224412, 'isClient'),
                 0xa3d5d0: (15224336, 'autorelease'),
                 0xa3d5e0: (15224424, 'objectType'),
                 0xa3d5e4: (15224428, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0xa3d5b4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3d5bc: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xa3d5c8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa3d5d4: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa3d5dc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(10736516, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10737128, 'rsbeq r2, r2, r8, asr r7')],
        calls=[(10736612, 'blx r2'), (10736796, 'bl loc.imp.objc_msgSend'), (10736876, 'blx r4'), (10737004, 'bl loc.imp.objc_msgSend'), (10737040, 'bl loc.imp.objc_msgSend')],
        branches=[(10736624, 'bge', 10737068), (10736684, 'bne', 10737048), (10736888, 'bne', 10736924), (10737044, 'b', 10737068), (10737048, 'b', 10737052), (10737064, 'b', 10736564)],
        semantics=('[TrainCar removeRider:] (imp 0x00a3d384, 154w): the rider detach.\n'),
    ),
    dict(
        name='tc_23',
        method='TrainCar -[swipeUpGesture]',
        types='v8@0:4',
        start=10737132,
        end=10737152,
        disasm='disasm_worldtileloader_tc_23.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3d600 (listing bound); next ObjC IMP 0x00a3d600 TrainCar -[riderBodyYRotationForBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10737132, 'sub sp, sp, 8'), (10737148, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar swipeUpGesture] (imp 0x00a3d5ec, 5w): empty (swipe not used).\n'),
    ),
    dict(
        name='tc_24',
        method='TrainCar -[riderBodyYRotationForBlockhead:]',
        types='f12@0:4@8',
        start=10737152,
        end=10737200,
        disasm='disasm_worldtileloader_tc_24.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3d630 (listing bound); next ObjC IMP 0x00a3d630 TrainCar -[cameraPosForBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10737152, 'sub sp, sp, 0x14'), (10737196, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[TrainCar riderBodyYRotationForBlockhead:] (imp 0x00a3d600, 12w): the rider Y rotation.\n'),
    ),
    dict(
        name='tc_25',
        method='TrainCar -[cameraPosForBlockhead:]',
        types='{Vector2=[2f]}12@0:4@8',
        start=10737200,
        end=10737340,
        disasm='disasm_worldtileloader_tc_25.txt',
        base_add=10737216,
        base_literal=10737336,
        boundary='ARM.exidx end 0x00a3d6bc (listing bound); next ObjC IMP 0x00a3d6bc TrainCar -[worldChanged:]',
        selectors={
                 0xa3d6b4: (15224448, 'renderPos'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(10737200, 'push {r4, sl, fp, lr}'), (10737336, 'rsbeq r2, r2, ip, lsr 9')],
        calls=[(10737284, 'bl loc.imp.objc_msgSend_stret'), (10737320, 'bl sym.imp.memset')],
        branches=[(10737268, 'beq', 10737292), (10737288, 'b', 10737324)],
        semantics=('[TrainCar cameraPosForBlockhead:] (imp 0x00a3d630, 35w): the camera accessor (stret + 8-byte nil memset).\n'),
    ),
    dict(
        name='tc_26',
        method='TrainCar -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=10737340,
        end=10738544,
        disasm='disasm_worldtileloader_tc_26.txt',
        base_add=10737356,
        base_literal=10738540,
        boundary='ARM.exidx end 0x00a3db70 (listing bound); next ObjC IMP 0x00a3db70 TrainCar -[actionTitle]',
        selectors={
                 0xa3db34: (15224304, 'maxNumberOfRiders'),
                 0xa3db50: (15224452, 'setNeedsRemoved:'),
                 0xa3db60: (15224456, 'itemType'),
                 0xa3db64: (15224460, 'freeBlockCreationSaveDict'),
                 0xa3db68: (15224464, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0xa3db30: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3db38: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xa3db40: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xa3db44: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa3db48: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa3db4c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa3db58: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa3db5c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(10737340, 'push {r4, r5, fp, lr}'), (10738540, 'rsbeq r2, r2, r0, lsr 8')],
        calls=[(10737444, 'blx r2'), (10738060, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10738088, 'bl sym.tileIsSolid_Tile_'), (10738156, 'bl loc.imp.objc_msgSend'), (10738256, 'bl loc.imp.objc_msgSend'), (10738288, 'bl loc.imp.objc_msgSend'), (10738392, 'bl loc.imp.objc_msgSend')],
        branches=[(10737456, 'bge', 10737552), (10737516, 'beq', 10737532), (10737528, 'b', 10737552), (10737532, 'b', 10737536), (10737548, 'b', 10737396), (10737560, 'bne', 10738472), (10737596, 'bne', 10738472), (10737632, 'bne', 10738472), (10737872, 'beq', 10738468), (10737944, 'bne', 10738404), (10737984, 'bne', 10738404), (10738080, 'beq', 10738400), (10738100, 'bne', 10738120), (10738116, 'beq', 10738400), (10738396, 'b', 10738472), (10738400, 'b', 10738468), (10738404, 'b', 10738408), (10738464, 'b', 10737720), (10738468, 'b', 10738472)],
        semantics=('[TrainCar worldChanged:] (imp 0x00a3d6bc, 301w): the support re-check - objc x4 + tileIsSolid.\n'),
    ),
    dict(
        name='tc_27',
        method='TrainCar -[actionTitle]',
        types='@8@0:4',
        start=10738544,
        end=10738620,
        disasm='disasm_worldtileloader_tc_27.txt',
        base_add=10738552,
        base_literal=10738588,
        boundary='ARM.exidx end 0x00a3dbbc (listing bound); next ObjC IMP 0x00a3dba0 TrainCar -[isDoubleHeight]',
        selectors={},
        imports={
                 0xa3db98: (16347896, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(10738544, 'sub sp, sp, 8'), (10738616, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar actionTitle] (imp 0x00a3db70, 12w): the action title (the station/rail family).\n'),
    ),
    dict(
        name='tc_28',
        method='TrainCar -[isDoubleHeight]',
        types='c8@0:4',
        start=10738592,
        end=10738620,
        disasm='disasm_worldtileloader_tc_28.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3dbbc (listing bound); next ObjC IMP 0x00a3dbbc TrainCar -[freeblockCreationItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10738592, 'sub sp, sp, 8'), (10738616, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar isDoubleHeight] (imp 0x00a3dba0, 7w): the double-height flag.\n'),
    ),
    dict(
        name='tc_29',
        method='TrainCar -[freeblockCreationItemType]',
        types='i8@0:4',
        start=10738620,
        end=10738696,
        disasm='disasm_worldtileloader_tc_29.txt',
        base_add=10738636,
        base_literal=10738692,
        boundary='ARM.exidx end 0x00a3dc08 (listing bound); next ObjC IMP 0x00a3dc08 TrainCar -[tapIsWithinBodyRadius:]',
        selectors={
                 0xa3dc00: (15224456, 'itemType'),
        },
        imports={
                 0xa3dbfc: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(10738620, 'push {fp, lr}'), (10738692, 'rsbeq r1, r2, r0, lsr 30')],
        calls=[(10738672, 'blx r3')],
        branches=[],
        semantics=('[TrainCar freeblockCreationItemType] (imp 0x00a3dbbc, 19w): the freeblock item type.\n'),
    ),
    dict(
        name='tc_30',
        method='TrainCar -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=10738696,
        end=10739704,
        disasm='disasm_worldtileloader_tc_30.txt',
        base_add=10738712,
        base_literal=10739700,
        boundary='ARM.exidx end 0x00a3dff8 (listing bound); next ObjC IMP 0x00a3dff8 TrainCar -[setNeedsRemoved:]',
        selectors={
                 0xa3dfe4: (15224468, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0xa3dfd8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa3dfe0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(10738696, 'push {r4, sl, fp, lr}'), (10739700, 'invalid')],
        calls=[(10738756, 'bl method.Vector2.operator_float__'), (10738800, 'bl method.Vector2.operator_float__'), (10738852, 'bl loc.imp.objc_msgSend'), (10738876, 'bl sym.imp.__aeabi_idiv'), (10738920, 'bl method.Vector2.operator_float__'), (10738964, 'bl method.Vector2.operator_float__'), (10739016, 'bl loc.imp.objc_msgSend'), (10739080, 'bl method.Vector2.operator_float__'), (10739124, 'bl method.Vector2.operator_float__'), (10739176, 'bl loc.imp.objc_msgSend'), (10739192, 'bl sym.imp.__aeabi_idiv'), (10739236, 'bl method.Vector2.operator_float__'), (10739280, 'bl method.Vector2.operator_float__'), (10739332, 'bl loc.imp.objc_msgSend'), (10739376, 'bl method.Vector2.operator_float__'), (10739412, 'bl method.Vector2.operator_float__'), (10739500, 'bl method.Vector2.operator_float__'), (10739536, 'bl method.Vector2.operator_float__'), (10739564, 'bl method.Vector2.operator_float__'), (10739600, 'bl method.Vector2.operator_float__')],
        branches=[(10738900, 'blt', 10739056), (10739052, 'b', 10739440), (10739216, 'bpl', 10739372), (10739368, 'b', 10739432), (10739468, 'bpl', 10739652), (10739492, 'ble', 10739652), (10739556, 'ble', 10739652), (10739636, 'bpl', 10739652), (10739648, 'b', 10739660)],
        semantics=('[TrainCar tapIsWithinBodyRadius:] (imp 0x00a3dc08, 252w): the tap test.\n'),
    ),
    dict(
        name='tc_31',
        method='TrainCar -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=10739704,
        end=10740096,
        disasm='disasm_worldtileloader_tc_31.txt',
        base_add=10739720,
        base_literal=10740092,
        boundary='ARM.exidx end 0x00a3e180 (listing bound); next ObjC IMP 0x00a3e180 TrainCar -[jumpsOnSwipe]',
        selectors={
                 0xa3e160: (15224304, 'maxNumberOfRiders'),
                 0xa3e164: (15224348, 'stopRiding'),
                 0xa3e174: (15224452, 'setNeedsRemoved:'),
        },
        imports={
                 0xa3e15c: (17151904, 'objc_msgSend'),
                 0xa3e170: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xa3e158: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xa3e168: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
        },
        classes={
                 0xa3e178: (15253028, 'OBJC_CLASS_$_TrainCar'),
        },
        instructions=[(10739704, 'push {r4, r5, fp, lr}'), (10740092, 'rsbeq r1, r2, r4, ror 21')],
        calls=[(10739848, 'blx r2'), (10739948, 'blx r2'), (10740044, 'blx r3')],
        branches=[(10739748, 'beq', 10739972), (10739784, 'bne', 10739972), (10739860, 'bge', 10739968), (10739964, 'b', 10739800), (10739968, 'b', 10739972)],
        semantics=('[TrainCar setNeedsRemoved:] (imp 0x00a3dff8, 98w): the removal flag.\n'),
    ),
    dict(
        name='tc_32',
        method='TrainCar -[jumpsOnSwipe]',
        types='c8@0:4',
        start=10740096,
        end=10740152,
        disasm='disasm_worldtileloader_tc_32.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3e1b8 (listing bound); next ObjC IMP 0x00a3e19c TrainCar -[rideDirection]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10740096, 'sub sp, sp, 8'), (10740148, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar jumpsOnSwipe] (imp 0x00a3e180, 7w): the swipe-jump flag.\n'),
    ),
    dict(
        name='tc_33',
        method='TrainCar -[rideDirection]',
        types='i8@0:4',
        start=10740124,
        end=10740152,
        disasm='disasm_worldtileloader_tc_33.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3e1b8 (listing bound); next ObjC IMP 0x00a3e1b8 TrainCar -[riderBodyZRotation]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10740124, 'sub sp, sp, 8'), (10740148, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar rideDirection] (imp 0x00a3e19c, 7w): the ride direction.\n'),
    ),
    dict(
        name='tc_34',
        method='TrainCar -[riderBodyZRotation]',
        types='f8@0:4',
        start=10740152,
        end=10740240,
        disasm='disasm_worldtileloader_tc_34.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3e210 (listing bound); next ObjC IMP 0x00a3e1e4 TrainCar -[riderAnimationTimer]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10740152, 'sub sp, sp, 0x10'), (10740236, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[TrainCar riderBodyZRotation] (imp 0x00a3e1b8, 11w): the rider Z rotation.\n'),
    ),
    dict(
        name='tc_35',
        method='TrainCar -[riderAnimationTimer]',
        types='f8@0:4',
        start=10740196,
        end=10740240,
        disasm='disasm_worldtileloader_tc_35.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3e210 (listing bound); next ObjC IMP 0x00a3e210 TrainCar -[itemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10740196, 'sub sp, sp, 0x10'), (10740236, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[TrainCar riderAnimationTimer] (imp 0x00a3e1e4, 11w): the rider animation timer.\n'),
    ),
    dict(
        name='tc_36',
        method='TrainCar -[itemType]',
        types='i8@0:4',
        start=10740240,
        end=10740296,
        disasm='disasm_worldtileloader_tc_36.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3e248 (listing bound); next ObjC IMP 0x00a3e22c TrainCar -[requiresFuel]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10740240, 'sub sp, sp, 8'), (10740292, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar itemType] (imp 0x00a3e210, 7w): returns **0** - the car has no item (unplaced-only?).\n'),
    ),
    dict(
        name='tc_37',
        method='TrainCar -[requiresFuel]',
        types='c8@0:4',
        start=10740268,
        end=10740296,
        disasm='disasm_worldtileloader_tc_37.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3e248 (listing bound); next ObjC IMP 0x00a3e248 TrainCar -[setPaused:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10740268, 'sub sp, sp, 8'), (10740292, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar requiresFuel] (imp 0x00a3e22c, 7w): the fuel flag (constant).\n'),
    ),
    dict(
        name='tc_38',
        method='TrainCar -[setPaused:]',
        types='v12@0:4c8',
        start=10740296,
        end=10740320,
        disasm='disasm_worldtileloader_tc_38.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3e260 (listing bound); next ObjC IMP 0x00a3e260 TrainCar -[isEngine]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10740296, 'sub sp, sp, 0xc'), (10740316, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar setPaused:] (imp 0x00a3e248, 6w): empty (pause is a no-op for cars).\n'),
    ),
    dict(
        name='tc_39',
        method='TrainCar -[isEngine]',
        types='c8@0:4',
        start=10740320,
        end=10740492,
        disasm='disasm_worldtileloader_tc_39.txt',
        base_add=10740356,
        base_literal=10740416,
        boundary='ARM.exidx end 0x00a3e30c (listing bound); next ObjC IMP 0x00a3e27c TrainCar -[leftWheelPos]',
        selectors={},
        imports={},
        ivars={
                 0xa3e2bc: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xa3e304: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
        },
        classes={},
        instructions=[(10740320, 'sub sp, sp, 8'), (10740488, 'rsbeq r1, r2, r0, lsr 16')],
        calls=[],
        branches=[],
        semantics=('[TrainCar isEngine] (imp 0x00a3e260, 7w): returns **0** - the car is NOT an engine (the SteamTrain isEngine=1 opposite).\n'),
    ),
    dict(
        name='tc_40',
        method='TrainCar -[leftWheelPos]',
        types='{Vector2=[2f]}8@0:4',
        start=10740348,
        end=10740492,
        disasm='disasm_worldtileloader_tc_40.txt',
        base_add=10740356,
        base_literal=10740416,
        boundary='ARM.exidx end 0x00a3e30c (listing bound); next ObjC IMP 0x00a3e2c4 TrainCar -[rightWheelPos]',
        selectors={},
        imports={},
        ivars={
                 0xa3e2bc: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xa3e304: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
        },
        classes={},
        instructions=[(10740348, 'sub sp, sp, 8'), (10740488, 'rsbeq r1, r2, r0, lsr 16')],
        calls=[],
        branches=[],
        semantics=('[TrainCar leftWheelPos] (imp 0x00a3e27c, 18w): the left-wheel position (the 8-byte x/y pair write - two str words per axis pair).\n'),
    ),
    dict(
        name='tc_41',
        method='TrainCar -[rightWheelPos]',
        types='{Vector2=[2f]}8@0:4',
        start=10740420,
        end=10740492,
        disasm='disasm_worldtileloader_tc_41.txt',
        base_add=10740428,
        base_literal=10740488,
        boundary='ARM.exidx end 0x00a3e30c (listing bound); next ObjC IMP 0x00a3e30c TrainCar -[setRightCar:]',
        selectors={},
        imports={},
        ivars={
                 0xa3e304: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
        },
        classes={},
        instructions=[(10740420, 'sub sp, sp, 8'), (10740488, 'rsbeq r1, r2, r0, lsr 16')],
        calls=[],
        branches=[],
        semantics=('[TrainCar rightWheelPos] (imp 0x00a3e2c4, 18w): the right-wheel position (pair write).\n'),
    ),
    dict(
        name='tc_42',
        method='TrainCar -[setRightCar:]',
        types='v12@0:4@8',
        start=10740492,
        end=10740820,
        disasm='disasm_worldtileloader_tc_42.txt',
        base_add=10740508,
        base_literal=10740816,
        boundary='ARM.exidx end 0x00a3e454 (listing bound); next ObjC IMP 0x00a3e454 TrainCar -[setLeftCar:]',
        selectors={
                 0xa3e448: (15224288, 'retain'),
                 0xa3e44c: (15224400, 'release'),
        },
        imports={
                 0xa3e444: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3e438: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa3e43c: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
                 0xa3e440: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(10740492, 'push {r4, r5, r6, sl, fp, lr}'), (10740816, 'invalid')],
        calls=[(10740716, 'blx r2'), (10740760, 'blx ip')],
        branches=[(10740556, 'bne', 10740632), (10740596, 'beq', 10740632)],
        semantics=('[TrainCar setRightCar:] (imp 0x00a3e30c, 82w): the right-neighbour linker - the nil gate (`cmp r0, 0; bne`) + the same-car equality compare (`cmp r2, r0; beq` = setting self is a no-op) + the pair stores (the consist links are 8-byte records!).\n'),
    ),
    dict(
        name='tc_43',
        method='TrainCar -[setLeftCar:]',
        types='v12@0:4@8',
        start=10740820,
        end=10741148,
        disasm='disasm_worldtileloader_tc_43.txt',
        base_add=10740836,
        base_literal=10741144,
        boundary='ARM.exidx end 0x00a3e59c (listing bound); next ObjC IMP 0x00a3e59c TrainCar -[leftCar]',
        selectors={
                 0xa3e590: (15224288, 'retain'),
                 0xa3e594: (15224400, 'release'),
        },
        imports={
                 0xa3e58c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3e580: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa3e584: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xa3e588: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(10740820, 'push {r4, r5, r6, sl, fp, lr}'), (10741144, 'rsbeq r1, r2, r8, lsl 13')],
        calls=[(10741044, 'blx r2'), (10741088, 'blx ip')],
        branches=[(10740884, 'bne', 10740960), (10740924, 'beq', 10740960)],
        semantics=('[TrainCar setLeftCar:] (imp 0x00a3e454, 82w): the left-neighbour linker (the same gate + store contract as setRightCar:).\n'),
    ),
    dict(
        name='tc_44',
        method='TrainCar -[leftCar]',
        types='@8@0:4',
        start=10741148,
        end=10741268,
        disasm='disasm_worldtileloader_tc_44.txt',
        base_add=10741156,
        base_literal=10741204,
        boundary='ARM.exidx end 0x00a3e614 (listing bound); next ObjC IMP 0x00a3e5d8 TrainCar -[rightCar]',
        selectors={},
        imports={},
        ivars={
                 0xa3e5d0: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xa3e60c: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
        },
        classes={},
        instructions=[(10741148, 'sub sp, sp, 8'), (10741264, 'rsbeq r1, r2, ip, lsl 10')],
        calls=[],
        branches=[],
        semantics=('[TrainCar leftCar] (imp 0x00a3e59c, 15w): the left-neighbour read (the 8-byte pair copy: two word loads/stores).\n'),
    ),
    dict(
        name='tc_45',
        method='TrainCar -[rightCar]',
        types='@8@0:4',
        start=10741208,
        end=10741268,
        disasm='disasm_worldtileloader_tc_45.txt',
        base_add=10741216,
        base_literal=10741264,
        boundary='ARM.exidx end 0x00a3e614 (listing bound); next ObjC IMP 0x00a3e614 TrainCar -[engineCar]',
        selectors={},
        imports={},
        ivars={
                 0xa3e60c: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
        },
        classes={},
        instructions=[(10741208, 'sub sp, sp, 8'), (10741264, 'rsbeq r1, r2, ip, lsl 10')],
        calls=[],
        branches=[],
        semantics=('[TrainCar rightCar] (imp 0x00a3e5d8, 15w): the right-neighbour read (pair copy).\n'),
    ),
    dict(
        name='tc_46',
        method='TrainCar -[engineCar]',
        types='@8@0:4',
        start=10741268,
        end=10741412,
        disasm='disasm_worldtileloader_tc_46.txt',
        base_add=10741284,
        base_literal=10741408,
        boundary='ARM.exidx end 0x00a3e6a4 (listing bound); next ObjC IMP 0x00a3e6a4 TrainCar -[setEngineCar:]',
        selectors={
                 0xa3e698: (15224444, 'isEngine'),
        },
        imports={
                 0xa3e694: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3e69c: (17161208, 'OBJC_IVAR_$_TrainCar.engineCar', 176),
        },
        classes={},
        instructions=[(10741268, 'push {fp, lr}'), (10741408, 'rsbeq r1, r2, r8, asr 9')],
        calls=[(10741324, 'blx r3')],
        branches=[(10741336, 'beq', 10741352), (10741348, 'b', 10741384)],
        semantics=('[TrainCar engineCar] (imp 0x00a3e614, 36w): the engine read with the nil gate + pair copy.\n'),
    ),
    dict(
        name='tc_47',
        method='TrainCar -[setEngineCar:]',
        types='v12@0:4@8',
        start=10741412,
        end=10742540,
        disasm='disasm_worldtileloader_tc_47.txt',
        base_add=10741428,
        base_literal=10742536,
        boundary='ARM.exidx end 0x00a3eb0c (listing bound); next ObjC IMP 0x00a3eb0c TrainCar -[actsAsInteractionObject]',
        selectors={
                 0xa3ead8: (15224444, 'isEngine'),
                 0xa3eaec: (15224288, 'retain'),
                 0xa3eaf0: (15224400, 'release'),
                 0xa3eaf4: (15224472, 'engineCar'),
                 0xa3eaf8: (15224476, 'setEngineCar:'),
                 0xa3eb04: (15224480, 'leftCar'),
        },
        imports={
                 0xa3ead4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3eadc: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa3eae0: (17161208, 'OBJC_IVAR_$_TrainCar.engineCar', 176),
                 0xa3eae4: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa3eae8: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xa3eafc: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
                 0xa3eb00: (17161260, 'OBJC_IVAR_$_TrainCar.engineIsRight', 180),
        },
        classes={},
        instructions=[(10741412, 'push {r4, r5, r6, r7, fp, lr}'), (10742536, 'rsbeq r1, r2, r8, lsr r4')],
        calls=[(10741472, 'blx ip'), (10741700, 'blx ip'), (10741744, 'blx ip'), (10741864, 'blx r2'), (10741984, 'blx r3'), (10742092, 'blx r2'), (10742212, 'blx r3'), (10742348, 'blx r3'), (10742416, 'blx r2')],
        branches=[(10741484, 'beq', 10741492), (10741488, 'b', 10742476), (10741524, 'bne', 10741600), (10741564, 'beq', 10741600), (10741796, 'beq', 10741988), (10741892, 'beq', 10741988), (10742024, 'beq', 10742216), (10742120, 'beq', 10742216), (10742252, 'beq', 10742476), (10742368, 'bne', 10742376), (10742372, 'b', 10742472), (10742428, 'beq', 10742468), (10742464, 'b', 10742472), (10742468, 'b', 10742296), (10742472, 'b', 10742476)],
        semantics=('[TrainCar setEngineCar:] (imp 0x00a3e6a4, 282w): the engine linker - the nil gate (`cmp r0, 0; beq`) + the nested presence check (`cmp r0, 0; bne`) + the chain stores: the car remembers its engine.\n'),
    ),
    dict(
        name='tc_48',
        method='TrainCar -[actsAsInteractionObject]',
        types='@8@0:4',
        start=10742540,
        end=10742616,
        disasm='disasm_worldtileloader_tc_48.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3eb58 (listing bound); next ObjC IMP 0x00a3eb28 TrainCar -[maxNumberOfRiders]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10742540, 'sub sp, sp, 8'), (10742612, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar actsAsInteractionObject] (imp 0x00a3eb0c, 7w): the interaction flag.\n'),
    ),
    dict(
        name='tc_49',
        method='TrainCar -[maxNumberOfRiders]',
        types='i8@0:4',
        start=10742568,
        end=10742616,
        disasm='disasm_worldtileloader_tc_49.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3eb58 (listing bound); next ObjC IMP 0x00a3eb44 TrainCar -[railOrStationNameChanged]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10742568, 'sub sp, sp, 8'), (10742612, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar maxNumberOfRiders] (imp 0x00a3eb28, 7w): returns **0** (the car carries no riders - they ride the engine).\n'),
    ),
    dict(
        name='tc_50',
        method='TrainCar -[railOrStationNameChanged]',
        types='v8@0:4',
        start=10742596,
        end=10742616,
        disasm='disasm_worldtileloader_tc_50.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3eb58 (listing bound); next ObjC IMP 0x00a3eb58 TrainCar -[blockheadUnloaded:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10742596, 'sub sp, sp, 8'), (10742612, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar railOrStationNameChanged] (imp 0x00a3eb44, 5w): the rail-name hook (empty).\n'),
    ),
    dict(
        name='tc_51',
        method='TrainCar -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=10742616,
        end=10742956,
        disasm='disasm_worldtileloader_tc_51.txt',
        base_add=10742632,
        base_literal=10742952,
        boundary='ARM.exidx end 0x00a3ecac (listing bound); next ObjC IMP 0x00a3ecac TrainCar -[removeFromMacroBlock]',
        selectors={
                 0xa3ec94: (15224304, 'maxNumberOfRiders'),
                 0xa3eca4: (15224336, 'autorelease'),
        },
        imports={
                 0xa3ec90: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3ec98: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
        },
        classes={},
        instructions=[(10742616, 'push {r4, sl, fp, lr}'), (10742952, 'rsbeq r0, r2, r4, lsl 31')],
        calls=[(10742712, 'blx r2'), (10742860, 'bl loc.imp.objc_msgSend')],
        branches=[(10742724, 'bge', 10742920), (10742784, 'bne', 10742900), (10742900, 'b', 10742904), (10742916, 'b', 10742664)],
        semantics=('[TrainCar blockheadUnloaded:] (imp 0x00a3eb58, 85w): the owner unload hook.\n'),
    ),
    dict(
        name='tc_52',
        method='TrainCar -[removeFromMacroBlock]',
        types='v8@0:4',
        start=10742956,
        end=10743120,
        disasm='disasm_worldtileloader_tc_52.txt',
        base_add=10742972,
        base_literal=10743116,
        boundary='ARM.exidx end 0x00a3ed50 (listing bound); next ObjC IMP 0x00a3ed50 TrainCar -[cleanup]',
        selectors={
                 0xa3ed3c: (15224484, 'removeFromMacroBlock'),
                 0xa3ed48: (15224488, 'cleanup'),
        },
        imports={
                 0xa3ed38: (17151900, 'objc_msgSendSuper2'),
                 0xa3ed44: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xa3ed40: (15253028, 'OBJC_CLASS_$_TrainCar'),
        },
        instructions=[(10742956, 'push {r4, sl, fp, lr}'), (10743116, 'rsbeq r0, r2, r0, lsr lr')],
        calls=[(10743040, 'blx ip'), (10743084, 'blx r2')],
        branches=[],
        semantics=('[TrainCar removeFromMacroBlock] (imp 0x00a3ecac, 41w): the removal hook.\n'),
    ),
    dict(
        name='tc_53',
        method='TrainCar -[cleanup]',
        types='v8@0:4',
        start=10743120,
        end=10743620,
        disasm='disasm_worldtileloader_tc_53.txt',
        base_add=10743136,
        base_literal=10743616,
        boundary='ARM.exidx end 0x00a3ef44 (listing bound); next ObjC IMP 0x00a3ef44 TrainCar -[connectsToOtherCars]',
        selectors={
                 0xa3ef2c: (15224336, 'autorelease'),
        },
        imports={
                 0xa3ef28: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3ef24: (17161256, 'OBJC_IVAR_$_TrainCar.rightWheelRail', 204),
                 0xa3ef30: (17161252, 'OBJC_IVAR_$_TrainCar.leftWheelRail', 200),
                 0xa3ef34: (17161208, 'OBJC_IVAR_$_TrainCar.engineCar', 176),
                 0xa3ef38: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xa3ef3c: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
        },
        classes={},
        instructions=[(10743120, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10743616, 'rsbeq r0, r2, ip, lsl 27')],
        calls=[(10743260, 'blx lr'), (10743332, 'blx r4'), (10743404, 'blx r4'), (10743476, 'blx r4'), (10743548, 'blx r4')],
        branches=[],
        semantics=('[TrainCar cleanup] (imp 0x00a3ed50, 125w): the consist cleanup - 5 calls (the unlink sweep).\n'),
    ),
    dict(
        name='tc_54',
        method='TrainCar -[connectsToOtherCars]',
        types='c8@0:4',
        start=10743620,
        end=10743676,
        disasm='disasm_worldtileloader_tc_54.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3ef7c (listing bound); next ObjC IMP 0x00a3ef60 TrainCar -[riderDPadShouldAllowUpDown]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10743620, 'sub sp, sp, 8'), (10743672, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar connectsToOtherCars] (imp 0x00a3ef44, 14w): returns **1** - the car connects to its neighbours (the consist chaining predicate!).\n'),
    ),
    dict(
        name='tc_55',
        method='TrainCar -[riderDPadShouldAllowUpDown]',
        types='c8@0:4',
        start=10743648,
        end=10743676,
        disasm='disasm_worldtileloader_tc_55.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a3ef7c (listing bound); next ObjC IMP 0x00a3ef7c TrainCar -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10743648, 'sub sp, sp, 8'), (10743672, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TrainCar riderDPadShouldAllowUpDown] (imp 0x00a3ef60, 7w): returns **0**.\n'),
    ),
    dict(
        name='tc_56',
        method='TrainCar -[.cxx_construct]',
        types='@8@0:4',
        start=10743676,
        end=10744172,
        disasm='disasm_worldtileloader_tc_56.txt',
        base_add=10743692,
        base_literal=10743916,
        boundary='ARM.exidx end 0x00a3f16c (listing bound); next ObjC IMP 0x00a3f1d0 FreightCar -[loadDerivedStuff]',
        selectors={},
        imports={},
        ivars={
                 0xa3f058: (17161264, 'OBJC_IVAR_$_TrainCar.visualVelocity', 128),
                 0xa3f05c: (17161240, 'OBJC_IVAR_$_TrainCar.rightWheelVel', 120),
                 0xa3f060: (17161236, 'OBJC_IVAR_$_TrainCar.leftWheelVel', 112),
                 0xa3f064: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xa3f068: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
        },
        classes={},
        instructions=[(10743676, 'push {fp, lr}'), (10744168, 'cmnmi pc, 0')],
        calls=[(10743728, 'bl method.Vector2.Vector2__'), (10743764, 'bl method.Vector2.Vector2__'), (10743800, 'bl method.Vector2.Vector2__'), (10743836, 'bl method.Vector2.Vector2__'), (10743872, 'bl method.Vector2.Vector2__'), (10744004, 'bl sym.clamp_float__float__float_'), (10744048, 'bl sym.clamp_float__float__float_'), (10744092, 'bl sym.clamp_float__float__float_'), (10744136, 'bl sym.clamp_float__float__float_')],
        branches=[],
        semantics=("[TrainCar .cxx_construct] (imp 0x00a3ef7c, 124w): the C++ member init - **`clamp_float` x4 + Vector2() x5** (the member vectors clamp to [0,1] - the same idiom as the tulip's E94).\n"),
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
        'batch': 'TrainCar (E99): the consist vehicle - the linking contract, the wheels and the car lifecycle; 57 bodies',
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
                        default=NATIVE / 'train_car.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale train_car.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
