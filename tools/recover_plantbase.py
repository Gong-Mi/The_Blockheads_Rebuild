#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The plants line: the Plant base class: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 2168 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/PLANT_BASE.md for the prose and boundaries.
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
    'bl 0x95767c': 0x0095767c,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.clampi_int__int__int_': 0x004c0b70,
    'bl sym.imp.lrand48': 0x001c2804,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsAirWaterOrSnow_Tile_': 0x00a126dc,
    'bl sym.tileIsPlant_Tile_': 0x00a13ce0,
}

SPECS = [
    dict(
        name='p_rmmacro',
        method='Plant -[removeFromMacroBlock]',
        types='v8@0:4',
        start=9785152,
        end=9785324,
        disasm='disasm_worldtileloader_p_rmmacro.txt',
        base_add=9785168,
        base_literal=9785320,
        boundary='ARM.exidx end 0x00954fec (listing bound); next ObjC IMP 0x00954fec Plant -[initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:]',
        selectors={
                 0x954fd8: (15219336, 'removeFromMacroBlock'),
                 0x954fe4: (15219332, 'clearAllTileContents'),
        },
        imports={
                 0x954fd4: (17151900, 'objc_msgSendSuper2'),
                 0x954fe0: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x954fdc: (15252932, 'OBJC_CLASS_$_Plant'),
        },
        instructions=[(9785152, 'push {r4, r5, r6, sl, fp, lr}'), (9785320, 'invalid')],
        calls=[(9785248, 'blx r5'), (9785288, 'blx r2')],
        branches=[],
        semantics=('[Plant removeFromMacroBlock] (imp 0x00954f40, 43w): the removal hook - the plant clears its macro-block presence through the shared chain (see cleartiles for the marker write).\n'),
    ),
    dict(
        name='p_ctor',
        method='Plant -[initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:]',
        types='@48@0:4@8@12{?=ii}16@24S28S32@36@40c44',
        start=9785324,
        end=9786528,
        disasm='disasm_worldtileloader_p_ctor.txt',
        base_add=9785340,
        base_literal=9786520,
        boundary='ARM.exidx end 0x009554a0 (listing bound); next ObjC IMP 0x009554a0 Plant -[loadSaveDictValues:]',
        selectors={
                 0x955444: (15219340, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0x955458: (15219344, 'getPlantAtPos:'),
                 0x955460: (15219348, 'worldContentsChangedAtPos:'),
                 0x955468: (15219352, 'release'),
                 0x95546c: (15219336, 'removeFromMacroBlock'),
                 0x955490: (15219356, 'objectType'),
                 0x955494: (15219360, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x955464: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x955448: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x95544c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x955450: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x955470: (17163012, 'OBJC_IVAR_$_Plant.treeDensityNoiseFunction', 60),
                 0x955478: (17155500, 'OBJC_IVAR_$_Plant.seasonOffsetNoiseFunction', 64),
                 0x95547c: (17155480, 'OBJC_IVAR_$_Plant.maxAgeGene', 54),
                 0x955480: (17163016, 'OBJC_IVAR_$_Plant.growthRateGene', 56),
                 0x95548c: (17155516, 'OBJC_IVAR_$_Plant.growthRate', 92),
        },
        classes={
                 0x95543c: (15252932, 'OBJC_CLASS_$_Plant'),
        },
        instructions=[(9785324, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9785564, 'bl loc.imp.objc_msgSendSuper2'), (9785680, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9785732, 'bl sym.tileIsPlant_Tile_'), (9785868, 'strb r2, [r1, 0xb]'), (9786524, 'andeq r0, r0, r0')],
        calls=[(9785564, 'bl loc.imp.objc_msgSendSuper2'), (9785680, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9785732, 'bl sym.tileIsPlant_Tile_'), (9785832, 'bl loc.imp.objc_msgSend'), (9785952, 'bl loc.imp.objc_msgSend'), (9786044, 'blx ip'), (9786064, 'blx r2'), (9786164, 'bl sym.clampi_int__int__int_'), (9786208, 'bl sym.clampi_int__int__int_'), (9786368, 'bl loc.imp.objc_msgSend'), (9786404, 'bl loc.imp.objc_msgSend')],
        branches=[(9785592, 'bne', 9785608), (9785604, 'b', 9786416), (9785700, 'beq', 9785720), (9785716, 'beq', 9786084), (9785744, 'beq', 9785968), (9785852, 'bne', 9785964), (9785964, 'b', 9785968), (9785976, 'bne', 9786080), (9786076, 'b', 9786416), (9786080, 'b', 9786084)],
        semantics=('[Plant initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:] (imp 0x00954fec, 301w): the placed ctor - super2 with the 6-arg frame (@0x9550dc) + nil gate (@0x9550f4); then the placement check: `tileAtWorldPositionLoaded` (@0x955150) + the **tile byte +0xb** test (@0x95516c) + **`tileIsPlant(Tile*)`** (@0x955184) + the occupancy write **`strb r2=0 [r1, 0xb]`** (@0x95520c: the +0xb marker is the plant-occupancy slot) over the ffffc8b4 chain.\n'),
    ),
    dict(
        name='p_ctornet',
        method='Plant -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=9788312,
        end=9788688,
        disasm='disasm_worldtileloader_p_ctornet.txt',
        base_add=9788328,
        base_literal=9788684,
        boundary='ARM.exidx end 0x00955d10 (listing bound); next ObjC IMP 0x00955d10 Plant -[dealloc]',
        selectors={
                 0x955cf4: (15219396, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x955d08: (15219400, 'getBytes:length:'),
        },
        imports={
                 0x955cf0: (17151900, 'objc_msgSendSuper2'),
                 0x955d04: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x955cfc: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0x955d00: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
        },
        classes={
                 0x955cf8: (15252932, 'OBJC_CLASS_$_Plant'),
        },
        instructions=[(9788312, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9788684, 'rsbseq sb, r0, r4, asr 30')],
        calls=[(9788464, 'blx r6'), (9788576, 'blx ip')],
        branches=[(9788492, 'bne', 9788508), (9788504, 'b', 9788644)],
        semantics=('[Plant initWithWorld:dynamicWorld:cache:netData:] (imp 0x00955b98, 94w): the netData ctor - super2 + the decode chain filling the plant state from the net record.\n'),
    ),
    dict(
        name='p_dealloc',
        method='Plant -[dealloc]',
        types='v8@0:4',
        start=9788688,
        end=9788796,
        disasm='disasm_worldtileloader_p_dealloc.txt',
        base_add=9788704,
        base_literal=9788792,
        boundary='ARM.exidx end 0x00955d7c (listing bound); next ObjC IMP 0x00955d7c Plant -[getSaveDict]',
        selectors={
                 0x955d70: (15219404, 'dealloc'),
        },
        imports={
                 0x955d6c: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0x955d74: (15252932, 'OBJC_CLASS_$_Plant'),
        },
        instructions=[(9788688, 'push {r4, sl, fp, lr}'), (9788792, 'rsbseq sb, r0, ip, asr 27')],
        calls=[(9788768, 'blx ip')],
        branches=[],
        semantics=('[Plant dealloc] (imp 0x00955d10, 27w): the teardown chain + super.\n'),
    ),
    dict(
        name='p_updatenet',
        method='Plant -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=9790620,
        end=9790704,
        disasm='disasm_worldtileloader_p_updatenet.txt',
        base_add=9790636,
        base_literal=9790700,
        boundary='ARM.exidx end 0x009564f0 (listing bound); next ObjC IMP 0x009564f0 Plant -[plantCreationNetData]',
        selectors={
                 0x9564e8: (15219432, 'creationNetDataForClient:'),
        },
        imports={
                 0x9564e4: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9790620, 'push {fp, lr}'), (9790700, 'rsbseq sb, r0, r0, asr 12')],
        calls=[(9790680, 'blx ip')],
        branches=[],
        semantics=('[Plant updateNetDataForClient:] (imp 0x0095649c, 21w): thin forwarder (ffffbcac family).\n'),
    ),
    dict(
        name='p_creationdata',
        method='Plant -[plantCreationNetData]',
        types='{PlantCreationNetData={DynamicObjectNetData=QIIC[7C]}SSSSsC[5C]}8@0:4',
        start=9790704,
        end=9790984,
        disasm='disasm_worldtileloader_p_creationdata.txt',
        base_add=9790720,
        base_literal=9790980,
        boundary='ARM.exidx end 0x00956608 (listing bound); next ObjC IMP 0x00956608 Plant -[creationNetDataForClient:]',
        selectors={
                 0x9565f4: (15219436, 'dynamicObjectNetData'),
        },
        imports={},
        ivars={
                 0x9565f8: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0x9565fc: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
        },
        classes={},
        instructions=[(9790704, 'push {r4, r5, r6, sl, fp, lr}'), (9790980, 'rsbseq sb, r0, ip, ror 11')],
        calls=[(9790788, 'bl loc.imp.objc_msgSend_stret'), (9790824, 'bl sym.imp.memset')],
        branches=[(9790772, 'beq', 9790796), (9790792, 'b', 9790828)],
        semantics=('[Plant plantCreationNetData] (imp 0x009564f0, 70w): the creation-record stret + memset (@the memset site) - the wire record builder.\n'),
    ),
    dict(
        name='p_creationdata2',
        method='Plant -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=9790984,
        end=9791208,
        disasm='disasm_worldtileloader_p_creationdata2.txt',
        base_add=9791000,
        base_literal=9791204,
        boundary='ARM.exidx end 0x009566e8 (listing bound); next ObjC IMP 0x009566e8 Plant -[remoteUpdate:]',
        selectors={
                 0x9566d4: (15219440, 'plantCreationNetData'),
                 0x9566dc: (15219444, 'dataWithBytes:length:'),
        },
        imports={
                 0x9566d8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x9566e0: (15248320, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(9790984, 'push {fp, lr}'), (9791204, 'ldrsbteq sb, [r0], -0x44')],
        calls=[(9791068, 'bl loc.imp.objc_msgSend_stret'), (9791104, 'bl sym.imp.memset'), (9791168, 'blx ip')],
        branches=[(9791052, 'beq', 9791076), (9791072, 'b', 9791108)],
        semantics=('[Plant creationNetDataForClient:] (imp 0x00956608, 56w): the client-facing creation record (stret family).\n'),
    ),
    dict(
        name='p_remoteupdate',
        method='Plant -[remoteUpdate:]',
        types='v12@0:4@8',
        start=9791208,
        end=9791496,
        disasm='disasm_worldtileloader_p_remoteupdate.txt',
        base_add=9791224,
        base_literal=9791492,
        boundary='ARM.exidx end 0x00956808 (listing bound); next ObjC IMP 0x00956808 Plant -[setFlowering:]',
        selectors={
                 0x9567ec: (15219448, 'remoteUpdate:'),
                 0x9567f8: (15219452, 'setFlowering:'),
                 0x956800: (15219400, 'getBytes:length:'),
        },
        imports={
                 0x9567e8: (17151900, 'objc_msgSendSuper2'),
                 0x9567f4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9567fc: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
        },
        classes={
                 0x9567f0: (15252932, 'OBJC_CLASS_$_Plant'),
        },
        instructions=[(9791208, 'push {r4, r5, r6, sl, fp, lr}'), (9791492, 'ldrshteq sb, [r0], -0x34')],
        calls=[(9791300, 'blx lr'), (9791392, 'blx lr'), (9791452, 'blx ip')],
        branches=[],
        semantics=('[Plant remoteUpdate:] (imp 0x009566e8, 72w): the network update - decode + state writes.\n'),
    ),
    dict(
        name='p_setflowering',
        method='Plant -[setFlowering:]',
        types='v12@0:4c8',
        start=9791496,
        end=9791564,
        disasm='disasm_worldtileloader_p_setflowering.txt',
        base_add=9791504,
        base_literal=9791560,
        boundary='ARM.exidx end 0x0095684c (listing bound); next ObjC IMP 0x0095684c Plant -[worldChanged:]',
        selectors={},
        imports={},
        ivars={
                 0x956844: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
        },
        classes={},
        instructions=[(9791496, 'sub sp, sp, 0xc'), (9791544, 'strb r0, [r1]'), (9791560, 'ldrsbteq sb, [r0], -0x2c')],
        calls=[],
        branches=[],
        semantics=('[Plant setFlowering:] (imp 0x00956808, 17w): the byte store through the **ffffcad4** cell (`strb r2, [r1]` @0x956838) - the flowering flag is at the cad4 slot.\n'),
    ),
    dict(
        name='p_worldchanged',
        method='Plant -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=9791564,
        end=9793052,
        disasm='disasm_worldtileloader_p_worldchanged.txt',
        base_add=9791580,
        base_literal=9793048,
        boundary='ARM.exidx end 0x00956e1c (listing bound); next ObjC IMP 0x00956e1c Plant -[isGrowingInCompost]',
        selectors={
                 0x956df4: (15219456, 'plantType'),
                 0x956dfc: (15219460, 'numberOfOccupiedTilesAbove'),
                 0x956e04: (15219464, 'macroTiles'),
                 0x956e08: (15219468, 'isRequiredSoilType:'),
                 0x956e10: (15219472, 'tileHarvested:removeBlockhead:correctToolMultiplier:'),
        },
        imports={
                 0x956df0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x956dec: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x956df8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x956e00: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(9791564, 'push {r4, sl, fp, lr}'), (9793048, 'invalid')],
        calls=[(9791676, 'blx r2'), (9792008, 'blx r2'), (9792252, 'blx r2'), (9792296, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9792372, 'blx r3'), (9792444, 'bl sym.makeIntpair_int__int_'), (9792492, 'bl loc.imp.objc_msgSend'), (9792664, 'blx r2'), (9792708, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9792736, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (9792844, 'bl sym.makeIntpair_int__int_'), (9792892, 'bl loc.imp.objc_msgSend')],
        branches=[(9791628, 'beq', 9791636), (9791632, 'b', 9792996), (9791684, 'bne', 9791692), (9791688, 'b', 9792996), (9791928, 'beq', 9792996), (9792044, 'bne', 9792932), (9792092, 'bgt', 9792932), (9792136, 'blt', 9792932), (9792316, 'beq', 9792508), (9792384, 'bne', 9792504), (9792500, 'b', 9792996), (9792504, 'b', 9792508), (9792540, 'bge', 9792928), (9792728, 'beq', 9792908), (9792748, 'beq', 9792764), (9792760, 'beq', 9792908), (9792908, 'b', 9792912), (9792924, 'b', 9792528), (9792928, 'b', 9792932), (9792932, 'b', 9792936), (9792992, 'b', 9791776)],
        semantics=("[Plant worldChanged:] (imp 0x0095684c, 372w): the support re-check - `tileAtWorldPosition` x2 + `makeIntpair` x2 + **`tileIsAirWaterOrSnow(Tile*)`** (the plant's supported-substrate test: air/water/snow) + objc notifies; 3 unclassified resolve as anchors.\n"),
    ),
    dict(
        name='p_compost',
        method='Plant -[isGrowingInCompost]',
        types='c8@0:4',
        start=9793052,
        end=9793272,
        disasm='disasm_worldtileloader_p_compost.txt',
        base_add=9793068,
        base_literal=9793264,
        boundary='ARM.exidx end 0x00956ef8 (listing bound); next ObjC IMP 0x00956ef8 Plant -[update:accurateDT:isSimulation:]',
        selectors={},
        imports={},
        ivars={
                 0x956ee8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x956eec: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(9793052, 'push {fp, lr}'), (9793268, 'andeq r0, r0, r0')],
        calls=[(9793148, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(9793168, 'beq', 9793236), (9793184, 'beq', 9793220), (9793200, 'beq', 9793220), (9793216, 'bne', 9793232), (9793228, 'b', 9793244), (9793232, 'b', 9793236)],
        semantics=('[Plant isGrowingInCompost] (imp 0x00956e1c, 55w): the compost check (helper + the ffffc8xx chain).\n'),
    ),
    dict(
        name='p_update',
        method='Plant -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=9793272,
        end=9794308,
        disasm='disasm_worldtileloader_p_update.txt',
        base_add=9793288,
        base_literal=9794304,
        boundary='ARM.exidx end 0x00957304 (listing bound); next ObjC IMP 0x00957304 Plant -[isRequiredSoilType:]',
        selectors={
                 0x9572d8: (15219464, 'macroTiles'),
                 0x9572e8: (15219476, 'isGrowingInCompost'),
                 0x9572f8: (15219356, 'objectType'),
                 0x9572fc: (15219360, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x9572d4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9572c0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x9572c4: (17161168, 'OBJC_IVAR_$_Plant.frozen', 76),
                 0x9572cc: (17163024, 'OBJC_IVAR_$_Plant.ageCounter', 96),
                 0x9572d0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9572dc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9572e0: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0x9572e4: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0x9572ec: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x9572f4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(9793272, 'push {r4, r5, fp, lr}'), (9794304, 'rsbseq r8, r0, r4, ror 23')],
        calls=[(9793656, 'blx r2'), (9793700, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9793936, 'blx r2'), (9794152, 'bl loc.imp.objc_msgSend'), (9794188, 'bl loc.imp.objc_msgSend')],
        branches=[(9793356, 'beq', 9793364), (9793360, 'b', 9794220), (9793396, 'bne', 9794220), (9793484, 'ble', 9794216), (9793720, 'beq', 9793832), (9793736, 'beq', 9793772), (9793752, 'beq', 9793772), (9793768, 'bne', 9793832), (9793892, 'blt', 9794020), (9793948, 'beq', 9794020), (9794216, 'b', 9794220)],
        semantics=('[Plant update:accurateDT:isSimulation:] (imp 0x00956ef8, 259w): the per-tick frame - objc x2 + `tileAtWorldPosition` x1 + the growth/season state writes.\n'),
    ),
    dict(
        name='p_soiltype',
        method='Plant -[isRequiredSoilType:]',
        types='c12@0:4i8',
        start=9794308,
        end=9794464,
        disasm='disasm_worldtileloader_p_soiltype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009573a0 (listing bound); next ObjC IMP 0x009573a0 Plant -[plantType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9794308, 'sub sp, sp, 0x10'), (9794460, 'bx lr')],
        calls=[],
        branches=[(9794340, 'beq', 9794444), (9794360, 'beq', 9794444), (9794380, 'beq', 9794444), (9794400, 'beq', 9794444), (9794420, 'beq', 9794444)],
        semantics=('[Plant isRequiredSoilType:] (imp 0x00957304, 39w): the soil membership - cmp against **{0x1b, 0x1c, 0x30, 0x31, 0x32}** (@the compare chain): plants accept the same soil codes as the trees PLUS the dead-tree markers 0x1b/0x1c (plants grow over dead trees).\n'),
    ),
    dict(
        name='p_planttype',
        method='Plant -[plantType]',
        types='i8@0:4',
        start=9794464,
        end=9794492,
        disasm='disasm_worldtileloader_p_planttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009573bc (listing bound); next ObjC IMP 0x009573bc Plant -[gatherProgressForTile:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9794464, 'sub sp, sp, 8'), (9794488, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Plant plantType] (imp 0x009573a0, 7w): the plant-type accessor (the per-subclass constant).\n'),
    ),
    dict(
        name='p_gatherprogress',
        method='Plant -[gatherProgressForTile:]',
        types='i16@0:4{?=ii}8',
        start=9794492,
        end=9794564,
        disasm='disasm_worldtileloader_p_gatherprogress.txt',
        base_add=9794504,
        base_literal=9794560,
        boundary='ARM.exidx end 0x00957404 (listing bound); next ObjC IMP 0x00957404 Plant -[tileHarvested:removeBlockhead:correctToolMultiplier:]',
        selectors={},
        imports={},
        ivars={
                 0x9573fc: (17155532, 'OBJC_IVAR_$_Plant.gatherProgress', 80),
        },
        classes={},
        instructions=[(9794492, 'push {fp, lr}'), (9794560, 'rsbseq r8, r0, r4, lsr 14')],
        calls=[],
        branches=[],
        semantics=('[Plant gatherProgressForTile:] (imp 0x009573bc, 18w): the gather-progress read (the per-tile progress slot).\n'),
    ),
    dict(
        name='p_harvested',
        method='Plant -[tileHarvested:removeBlockhead:correctToolMultiplier:]',
        types='i24@0:4{?=ii}8@16i20',
        start=9794564,
        end=9794676,
        disasm='disasm_worldtileloader_p_harvested.txt',
        base_add=9794580,
        base_literal=9794672,
        boundary='ARM.exidx end 0x00957474 (listing bound); next ObjC IMP 0x00957474 Plant -[setGatherProgress:forTile:]',
        selectors={
                 0x95746c: (15219480, 'removePlantWithoutCreatingFreeblocks'),
        },
        imports={
                 0x957468: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9794564, 'push {r4, r5, r6, r7, fp, lr}'), (9794672, 'ldrsbteq r8, [r0], -0x68')],
        calls=[(9794648, 'blx r6')],
        branches=[],
        semantics=('[Plant tileHarvested:removeBlockhead:correctToolMultiplier:] (imp 0x00957404, 28w): the harvest hook - forwarder via ffffbcac + ffe24024 (@0x957458).\n'),
    ),
    dict(
        name='p_setgather',
        method='Plant -[setGatherProgress:forTile:]',
        types='v20@0:4i8{?=ii}12',
        start=9794676,
        end=9794760,
        disasm='disasm_worldtileloader_p_setgather.txt',
        base_add=9794688,
        base_literal=9794756,
        boundary='ARM.exidx end 0x009574c8 (listing bound); next ObjC IMP 0x009574c8 Plant -[removePlantWithoutCreatingFreeblocks]',
        selectors={},
        imports={},
        ivars={
                 0x9574c0: (17155532, 'OBJC_IVAR_$_Plant.gatherProgress', 80),
        },
        classes={},
        instructions=[(9794676, 'push {r4, lr}'), (9794756, 'rsbseq r8, r0, ip, ror 12')],
        calls=[],
        branches=[],
        semantics=('[Plant setGatherProgress:forTile:] (imp 0x00957474, 21w): the gather-progress write.\n'),
    ),
    dict(
        name='p_removeplant',
        method='Plant -[removePlantWithoutCreatingFreeblocks]',
        types='v8@0:4',
        start=9794760,
        end=9795388,
        disasm='disasm_worldtileloader_p_removeplant.txt',
        base_add=9794776,
        base_literal=9795016,
        boundary='ARM.exidx end 0x0095773c (listing bound); next ObjC IMP 0x009575cc Plant -[maxAgeGeneVariation]',
        selectors={
                 0x9575b0: (15219484, 'setNeedsRemoved:'),
                 0x9575c0: (15219356, 'objectType'),
                 0x9575c4: (15219360, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={},
        ivars={
                 0x9575ac: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x9575b8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x9575bc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x957674: (17155480, 'OBJC_IVAR_$_Plant.maxAgeGene', 54),
                 0x957734: (17163016, 'OBJC_IVAR_$_Plant.growthRateGene', 56),
        },
        classes={},
        instructions=[(9794760, 'push {fp, lr}'), (9795384, 'rsbseq r8, r0, r0, asr r4')],
        calls=[(9794840, 'bl loc.imp.objc_msgSend'), (9794916, 'bl loc.imp.objc_msgSend'), (9794952, 'bl loc.imp.objc_msgSend'), (9795076, 'bl 0x95767c'), (9795160, 'bl sym.clampi_int__int__int_'), (9795204, 'bl sym.imp.lrand48'), (9795268, 'bl 0x95767c'), (9795352, 'bl sym.clampi_int__int__int_')],
        branches=[],
        semantics=('[Plant removePlantWithoutCreatingFreeblocks] (imp 0x009574c8, 157w): the plant removal - objc x3 + the local helper 0x95767c x2 + **`clampi(int,int,int)` x2** + **`lrand48` x1**: the randomized droop/spawn gate (lrand48 picks the outcome; clampi clamps the derived values).\n'),
    ),
    dict(
        name='p_maxagegene',
        method='Plant -[maxAgeGeneVariation]',
        types='S8@0:4',
        start=9795020,
        end=9795388,
        disasm='disasm_worldtileloader_p_maxagegene.txt',
        base_add=9795036,
        base_literal=9795192,
        boundary='ARM.exidx end 0x0095773c (listing bound); next ObjC IMP 0x0095768c Plant -[growthRateGeneVariation]',
        selectors={},
        imports={},
        ivars={
                 0x957674: (17155480, 'OBJC_IVAR_$_Plant.maxAgeGene', 54),
                 0x957734: (17163016, 'OBJC_IVAR_$_Plant.growthRateGene', 56),
        },
        classes={},
        instructions=[(9795020, 'push {fp, lr}'), (9795384, 'rsbseq r8, r0, r0, asr r4')],
        calls=[(9795076, 'bl 0x95767c'), (9795160, 'bl sym.clampi_int__int__int_'), (9795204, 'bl sym.imp.lrand48'), (9795268, 'bl 0x95767c'), (9795352, 'bl sym.clampi_int__int__int_')],
        branches=[],
        semantics=('[Plant maxAgeGeneVariation] (imp 0x009575cc, 92w): the gene-variation constant - `0xff` clamp via the helper 0x95767c + **`clampi(int,int,int)`** into [0, 0xff].\n'),
    ),
    dict(
        name='p_growthgene',
        method='Plant -[growthRateGeneVariation]',
        types='S8@0:4',
        start=9795212,
        end=9795388,
        disasm='disasm_worldtileloader_p_growthgene.txt',
        base_add=9795228,
        base_literal=9795384,
        boundary='ARM.exidx end 0x0095773c (listing bound); next ObjC IMP 0x0095773c Plant -[isFlowering]',
        selectors={},
        imports={},
        ivars={
                 0x957734: (17163016, 'OBJC_IVAR_$_Plant.growthRateGene', 56),
        },
        classes={},
        instructions=[(9795212, 'push {fp, lr}'), (9795384, 'rsbseq r8, r0, r0, asr r4')],
        calls=[(9795268, 'bl 0x95767c'), (9795352, 'bl sym.clampi_int__int__int_')],
        branches=[],
        semantics=('[Plant growthRateGeneVariation] (imp 0x0095768c, 44w): the mirror (0xff clamp + clampi).\n'),
    ),
    dict(
        name='p_isflowering',
        method='Plant -[isFlowering]',
        types='c8@0:4',
        start=9795388,
        end=9795476,
        disasm='disasm_worldtileloader_p_isflowering.txt',
        base_add=9795396,
        base_literal=9795444,
        boundary='ARM.exidx end 0x00957794 (listing bound); next ObjC IMP 0x00957778 Plant -[droppedItemType]',
        selectors={},
        imports={},
        ivars={
                 0x957770: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
        },
        classes={},
        instructions=[(9795388, 'sub sp, sp, 8'), (9795472, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Plant isFlowering] (imp 0x0095773c, 22w): the flowering flag read (the cad4 slot).\n'),
    ),
    dict(
        name='p_droppeditem',
        method='Plant -[droppedItemType]',
        types='i8@0:4',
        start=9795448,
        end=9795476,
        disasm='disasm_worldtileloader_p_droppeditem.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00957794 (listing bound); next ObjC IMP 0x00957794 Plant -[tileIsKindOfSelf:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9795448, 'sub sp, sp, 8'), (9795472, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Plant droppedItemType] (imp 0x00957778, 7w): the dropped-item accessor (per-subclass constant).\n'),
    ),
    dict(
        name='p_kindself',
        method='Plant -[tileIsKindOfSelf:]',
        types='c12@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8',
        start=9795476,
        end=9795508,
        disasm='disasm_worldtileloader_p_kindself.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009577b4 (listing bound); next ObjC IMP 0x009577b4 Plant -[clearAllTileContents]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9795476, 'sub sp, sp, 0xc'), (9795504, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Plant tileIsKindOfSelf:] (imp 0x00957794, 8w): the membership test (the plant marker byte family).\n'),
    ),
    dict(
        name='p_cleartiles',
        method='Plant -[clearAllTileContents]',
        types='v8@0:4',
        start=9795508,
        end=9796340,
        disasm='disasm_worldtileloader_p_cleartiles.txt',
        base_add=9795524,
        base_literal=9796336,
        boundary='ARM.exidx end 0x00957af4 (listing bound); next ObjC IMP 0x00957af4 Plant -[setNeedsRemoved:]',
        selectors={
                 0x957ad4: (15219488, 'tileIsKindOfSelf:'),
                 0x957ae0: (15219348, 'worldContentsChangedAtPos:'),
                 0x957ae4: (15219492, 'numberOfOccupiedTilesBelow'),
                 0x957ae8: (15219460, 'numberOfOccupiedTilesAbove'),
        },
        imports={
                 0x957ad0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x957ac8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x957acc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x957ad8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(9795508, 'push {fp, lr}'), (9795608, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9795704, 'strb r1, [r0, 0xb]'), (9796336, 'rsbseq r8, r0, r8, lsr 6')],
        calls=[(9795608, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9795680, 'blx r3'), (9795788, 'bl sym.makeIntpair_int__int_'), (9795816, 'bl loc.imp.objc_msgSend'), (9795880, 'blx r3'), (9795944, 'blx r2'), (9796044, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9796116, 'blx r3'), (9796236, 'bl sym.makeIntpair_int__int_'), (9796264, 'bl loc.imp.objc_msgSend')],
        branches=[(9795628, 'beq', 9795820), (9795692, 'beq', 9795820), (9795956, 'bge', 9796288), (9796064, 'beq', 9796268), (9796128, 'beq', 9796268), (9796268, 'b', 9796272), (9796284, 'b', 9795896)],
        semantics=("[Plant clearAllTileContents] (imp 0x009577b4, 208w): clears the plant's tiles - `tileAtWorldPositionLoaded` (@0x957818) then the **`strb r1=0 [r0, 0xb]`** marker clear (@0x957878) + the ffffc8b4/c89c/c8a0 chain; the +0xb byte is the plant-occupancy slot (shared with the ctor's write).\n"),
    ),
    dict(
        name='p_setneedsremoved',
        method='Plant -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=9796340,
        end=9796580,
        disasm='disasm_worldtileloader_p_setneedsremoved.txt',
        base_add=9796356,
        base_literal=9796576,
        boundary='ARM.exidx end 0x00957be4 (listing bound); next ObjC IMP 0x00957be4 Plant -[canBreed]',
        selectors={
                 0x957bd0: (15219332, 'clearAllTileContents'),
                 0x957bd8: (15219484, 'setNeedsRemoved:'),
        },
        imports={
                 0x957bcc: (17151904, 'objc_msgSend'),
                 0x957bd4: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x957bc8: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={
                 0x957bdc: (15252932, 'OBJC_CLASS_$_Plant'),
        },
        instructions=[(9796340, 'push {r4, sl, fp, lr}'), (9796576, 'rsbseq r7, r0, r8, ror 31')],
        calls=[(9796464, 'blx r2'), (9796540, 'blx r3')],
        branches=[(9796384, 'beq', 9796468), (9796420, 'bne', 9796468)],
        semantics=('[Plant setNeedsRemoved:] (imp 0x00957af4, 60w): the removed-flag chain (ffffbca8 super + sxtb gate).\n'),
    ),
    dict(
        name='p_canbreed',
        method='Plant -[canBreed]',
        types='c8@0:4',
        start=9796580,
        end=9796692,
        disasm='disasm_worldtileloader_p_canbreed.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00957c54 (listing bound); next ObjC IMP 0x00957c00 Plant -[occupiesForegroundContents]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9796580, 'sub sp, sp, 8'), (9796688, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Plant canBreed] (imp 0x00957be4, 28w): the breeding predicate (per-subclass / state).\n'),
    ),
    dict(
        name='p_occupiesfg',
        method='Plant -[occupiesForegroundContents]',
        types='c8@0:4',
        start=9796608,
        end=9796692,
        disasm='disasm_worldtileloader_p_occupiesfg.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00957c54 (listing bound); next ObjC IMP 0x00957c1c Plant -[numberOfOccupiedTilesAbove]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9796608, 'sub sp, sp, 8'), (9796688, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Plant occupiesForegroundContents] (imp 0x00957c00, 21w): the foreground-occupancy predicate.\n'),
    ),
    dict(
        name='p_tilesabove',
        method='Plant -[numberOfOccupiedTilesAbove]',
        types='i8@0:4',
        start=9796636,
        end=9796692,
        disasm='disasm_worldtileloader_p_tilesabove.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00957c54 (listing bound); next ObjC IMP 0x00957c38 Plant -[numberOfOccupiedTilesBelow]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9796636, 'sub sp, sp, 8'), (9796688, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Plant numberOfOccupiedTilesAbove] (imp 0x00957c1c, 14w): returns the planted-stalk height above (the constant/thin read).\n'),
    ),
    dict(
        name='p_tilesbelow',
        method='Plant -[numberOfOccupiedTilesBelow]',
        types='i8@0:4',
        start=9796664,
        end=9796692,
        disasm='disasm_worldtileloader_p_tilesbelow.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00957c54 (listing bound); next ObjC IMP 0x00957db4 PortalChestManager -[initWithWorld:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9796664, 'sub sp, sp, 8'), (9796688, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Plant numberOfOccupiedTilesBelow] (imp 0x00957c38, 7w): the below count (constant).\n'),
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
        'batch': 'Plant base class (E88): the engine of every plant - ctor/net/save pair, worldChanged, update, harvest pair, the +0xb slot; 29 bodies',
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
                        default=NATIVE / 'plant_base.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale plant_base.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
