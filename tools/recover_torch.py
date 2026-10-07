#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the Torch class (the primitive artificial light): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 10130 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/TORCH.md for the prose and boundaries.
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
    'bl 0x4b6594': 0x004b6594,
    'bl 0x4b6d64': 0x004b6d64,
    'bl 0x4bda38': 0x004bda38,
    'bl 0x4bdac0': 0x004bdac0,
    'bl 0x4bdca8': 0x004bdca8,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_': 0x00d948fc,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_': 0x00a19670,
    'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_': 0x00a197b4,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileContainsDoor_Tile_': 0x00a12818,
    'bl sym.tileIsHalfDepth_Tile__World__intpair_': 0x00a14450,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
    'bl sym.torchConnectionTypeForPos_intpair__World__ItemType_': 0x004b4444,
    'bl sym.updateQuadBufferTexCoords_float__int__float__float__float__float_': 0x00d91b30,
}

SPECS = [
    dict(
        name='t_initsubderived',
        method='Torch -[initSubDerivedItems]',
        types='v8@0:4',
        start=4934176,
        end=4935320,
        disasm='disasm_worldtileloader_t_initsubderived.txt',
        base_add=4934192,
        base_literal=4935316,
        boundary='ARM.exidx end 0x004b4e98 (listing bound); next ObjC IMP 0x004b4e98 Torch -[getLightRGB]',
        selectors={
                 0x4b4e90: (15192416, 'macroTiles'),
        },
        imports={},
        ivars={
                 0x4b4e74: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4b4e78: (17154948, 'OBJC_IVAR_$_Torch.chandelier', 78),
                 0x4b4e7c: (17154952, 'OBJC_IVAR_$_Torch.animates', 76),
                 0x4b4e80: (17154956, 'OBJC_IVAR_$_Torch.flatOnSideAndBottom', 77),
                 0x4b4e88: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4b4e8c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(4934176, 'push {fp, lr}'), (4934232, 'cmp r0, 0x94'), (4934416, 'moveq r0, 1'), (4934460, 'strb r0, [ip]'), (4934524, 'cmp r1, 0x4b'), (4935316, 'ldrhteq fp, [sl], ip')],
        calls=[(4935124, 'bl loc.imp.objc_msgSend'), (4935168, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (4935228, 'bl loc.imp.objc_msgSend'), (4935272, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(4934244, 'beq', 4934424), (4934288, 'beq', 4934424), (4934332, 'beq', 4934424), (4934376, 'beq', 4934424), (4934488, 'bne', 4934848), (4934532, 'beq', 4934848), (4934576, 'beq', 4934848), (4934620, 'beq', 4934848), (4934664, 'beq', 4934848), (4934708, 'beq', 4934848), (4934752, 'beq', 4934848), (4934796, 'beq', 4934848), (4934912, 'bne', 4935008), (4934956, 'beq', 4935008)],
        semantics=("[Torch initSubDerivedItems] (imp 0x004b4a20, 286w): derives the torch's sub-state from the **block type it sits on**: the block byte (ffffc88c chain) is compared against **0x94/0x93/0x92/0x91 (148..145)** (beq arms @0x4b4a64-0x4b4ae8), the 0x95 (149) arm booleanizes (`moveq 1` @0x4b4b10), then a second chain across **0x4b ('K') / 0x4c ('L') / ...** block codes; the derived flag is strored via strb (ffffc890 cell @0x4b4b3c). The 0x91..0x95 family is the torch-flame block set of the world format.\n"),
    ),
    dict(
        name='t_getlightrgb',
        method='Torch -[getLightRGB]',
        types='{Vector=[4f]}8@0:4',
        start=4935320,
        end=4936364,
        disasm='disasm_worldtileloader_t_getlightrgb.txt',
        base_add=4935336,
        base_literal=4936360,
        boundary='ARM.exidx end 0x004b52ac (listing bound); next ObjC IMP 0x004b5300 Torch -[initWithWorld:dynamicWorld:atPosition:cache:type:dataA:dataB:saveDict:placedByClient:]',
        selectors={},
        imports={},
        ivars={
                 0x4b52a4: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
        },
        classes={},
        instructions=[(4935320, 'push {r4, r5, fp, lr}'), (4935412, 'movw r0, 0x7f'), (4935472, 'movw r0, 0xdc'), (4935612, 'movw r0, 0xaa'), (4936360, 'adcseq sl, sl, r4, asr 24')],
        calls=[(4936340, 'bl method.Vector.Vector_float__float__float_')],
        branches=[(4935408, 'bne', 4935436), (4935432, 'b', 4936288), (4935468, 'bne', 4935500), (4935496, 'b', 4936284), (4935532, 'beq', 4935612), (4935568, 'beq', 4935612), (4935608, 'bne', 4935636), (4935632, 'b', 4936280), (4935668, 'bne', 4935696), (4935692, 'b', 4936276), (4935728, 'bne', 4935756), (4935752, 'b', 4936272), (4935788, 'bne', 4935816), (4935812, 'b', 4936268), (4935848, 'bne', 4935880), (4935876, 'b', 4936264), (4935912, 'bne', 4935940), (4935936, 'b', 4936260), (4935972, 'bne', 4936000), (4935996, 'b', 4936256), (4936032, 'bne', 4936060), (4936056, 'b', 4936252), (4936092, 'bne', 4936120), (4936116, 'b', 4936248), (4936152, 'bne', 4936184), (4936180, 'b', 4936244), (4936216, 'bne', 4936240), (4936240, 'b', 4936244), (4936244, 'b', 4936248), (4936248, 'b', 4936252), (4936252, 'b', 4936256), (4936256, 'b', 4936260), (4936260, 'b', 4936264), (4936264, 'b', 4936268), (4936268, 'b', 4936272), (4936272, 'b', 4936276), (4936276, 'b', 4936280), (4936280, 'b', 4936284), (4936284, 'b', 4936288)],
        semantics=("[Torch getLightRGB] (imp 0x004b4e98, 261w): the **light color table by block type**: block 0x2f ('/') → **(0x7f, 0xff, 0x37-const)** (@0x4b4ef4: 127/255 + the 0x37 stored at [sp,0xc]); block **0xb7 (183) → (0xdc, 0x64, 0xc) = (220, 100, 12)** the orange flame (@0x4b4f30); block **0x96 (150) / 0xfe (254) / 0x102 (258)** → (0xaa, 0x12c, ..) (@0x4b4fbc); the returns are packed RGB bytes via the {Vector=[4f]} return type. The block-type universe 0x2f/0xb7/0x96/0xfe/0x102 matches the fire/torch block family seen in t_worldcontents.\n"),
    ),
    dict(
        name='t_ctor_placed',
        method='Torch -[initWithWorld:dynamicWorld:atPosition:cache:type:dataA:dataB:saveDict:placedByClient:]',
        types='@48@0:4@8@12{?=ii}16@24i28S32S36@40@44',
        start=4936448,
        end=4938760,
        disasm='disasm_worldtileloader_t_ctor_placed.txt',
        base_add=4936464,
        base_literal=4938756,
        boundary='ARM.exidx end 0x004b5c08 (listing bound); next ObjC IMP 0x004b5c1c Torch -[objectType]',
        selectors={
                 0x4b5bac: (15192420, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0x4b5bc4: (15192428, 'objectForKey:'),
                 0x4b5bcc: (15192424, 'retain'),
                 0x4b5bd0: (15192432, 'getLightRGB'),
                 0x4b5be0: (15192436, 'alloc'),
                 0x4b5bf4: (15192440, 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'),
                 0x4b5bf8: (15192444, 'initSubDerivedItems'),
        },
        imports={
                 0x4b5bbc: (16200824, '__CFConstantStringClassReference'),
                 0x4b5bc0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4b5bb0: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
                 0x4b5bb4: (17154972, 'OBJC_IVAR_$_Torch.dataA', 80),
                 0x4b5bb8: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4b5bc8: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x4b5bd4: (17154980, 'OBJC_IVAR_$_Torch.light', 56),
                 0x4b5be4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4b5be8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4b5bec: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4b5bf0: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x4b5bfc: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
        },
        classes={
                 0x4b5ba4: (15252524, 'OBJC_CLASS_$_Torch'),
                 0x4b5bd8: (15244944, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(4936448, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4936688, 'bl loc.imp.objc_msgSendSuper2'), (4936780, 'str lr, [ip]'), (4936820, 'strh r3, [r1]'), (4936880, 'blx r2'), (4938756, 'ldrsbteq sl, [sl], ip')],
        calls=[(4936688, 'bl loc.imp.objc_msgSendSuper2'), (4936880, 'blx r2'), (4936968, 'blx r3'), (4937068, 'blx lr'), (4937084, 'blx r2'), (4937164, 'bl loc.imp.objc_msgSend_stret'), (4937200, 'bl sym.imp.memset'), (4937208, 'bl method.Vector.operator_float__'), (4937236, 'bl method.Vector.operator_float__'), (4937264, 'bl method.Vector.operator_float__'), (4938228, 'bl loc.imp.objc_msgSend'), (4938448, 'bl loc.imp.objc_msgSend'), (4938568, 'bl sym.torchConnectionTypeForPos_intpair__World__ItemType_'), (4938636, 'blx r3')],
        branches=[(4936716, 'bne', 4936732), (4936728, 'b', 4938648), (4936832, 'beq', 4936908), (4936904, 'b', 4937112), (4936980, 'beq', 4937108), (4937108, 'b', 4937112), (4937148, 'beq', 4937172), (4937168, 'b', 4937204), (4937332, 'bne', 4937348), (4937344, 'b', 4938036), (4937380, 'bne', 4937404), (4937400, 'b', 4938032), (4937436, 'beq', 4937516), (4937472, 'beq', 4937516), (4937512, 'bne', 4937528), (4937524, 'b', 4938028), (4937560, 'bne', 4937584), (4937580, 'b', 4938024), (4937616, 'bne', 4937640), (4937636, 'b', 4938020), (4937672, 'bne', 4937696), (4937692, 'b', 4938016), (4937728, 'bne', 4937752), (4937748, 'b', 4938012), (4937784, 'bne', 4937808), (4937804, 'b', 4938008), (4937840, 'beq', 4937988), (4937876, 'beq', 4937988), (4937912, 'beq', 4937988), (4937948, 'beq', 4937988), (4937984, 'bne', 4938004), (4938004, 'b', 4938008), (4938008, 'b', 4938012), (4938012, 'b', 4938016), (4938016, 'b', 4938020), (4938020, 'b', 4938024), (4938024, 'b', 4938028), (4938028, 'b', 4938032), (4938032, 'b', 4938036), (4938068, 'beq', 4938472), (4938112, 'bne', 4938128), (4938124, 'b', 4938180), (4938164, 'bne', 4938176), (4938176, 'b', 4938180)],
        semantics=('[Torch initWithWorld:...type:dataA:dataB:saveDict:placedByClient:] (imp 0x004b5300, 578w): super2 (@0x4b53f0) + nil gate (@0x4b5408); the dataA/dataB **halfwords** (strh r8/r7 @0x4b5370-0x4b5374) are saved through the ffffc8a4/c8a8 ivar cells (`strh ip [r3]` = dataB @0x4b5460, `strh r3 [r1]` = dataA @0x4b5474), the type/value through ffffc88c (`str lr [ip]` @0x4b544c); then the ffffc8ac/bcac + ffe1d674 cache-insert callback (@0x4b54b0). The save-dict decode chain runs the ffe2c138/ffe1d670 pulls.\n'),
    ),
    dict(
        name='t_objecttype',
        method='Torch -[objectType]',
        types='i8@0:4',
        start=4938780,
        end=4938868,
        disasm='disasm_worldtileloader_t_objecttype.txt',
        base_add=4938816,
        base_literal=4938864,
        boundary='ARM.exidx end 0x004b5c74 (listing bound); next ObjC IMP 0x004b5c38 Torch -[freeblockCreationItemType]',
        selectors={},
        imports={},
        ivars={
                 0x4b5c6c: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
        },
        classes={},
        instructions=[(4938780, 'sub sp, sp, 8'), (4938864, 'adcseq sb, sl, ip, lsr 29')],
        calls=[],
        branches=[],
        semantics=("[Torch objectType] (imp 0x004b5c1c, 22w): returns **0x11 (17)** - the torch's dynamic-object type code, matching the pinned torch=17 of the accessor family.\n"),
    ),
    dict(
        name='t_fbitemtype',
        method='Torch -[freeblockCreationItemType]',
        types='i8@0:4',
        start=4938808,
        end=4938868,
        disasm='disasm_worldtileloader_t_fbitemtype.txt',
        base_add=4938816,
        base_literal=4938864,
        boundary='ARM.exidx end 0x004b5c74 (listing bound); next ObjC IMP 0x004b5c74 Torch -[freeBlockCreationSaveDict]',
        selectors={},
        imports={},
        ivars={
                 0x4b5c6c: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
        },
        classes={},
        instructions=[(4938808, 'sub sp, sp, 8'), (4938864, 'adcseq sb, sl, ip, lsr 29')],
        calls=[],
        branches=[],
        semantics=("[Torch freeblockCreationItemType] (imp 0x004b5c38, 15w): reads an ivar through the ffffc88c cell (the torch's creation item type).\n"),
    ),
    dict(
        name='t_fbsavedict',
        method='Torch -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=4938868,
        end=4938944,
        disasm='disasm_worldtileloader_t_fbsavedict.txt',
        base_add=4938884,
        base_literal=4938940,
        boundary='ARM.exidx end 0x004b5cc0 (listing bound); next ObjC IMP 0x004b5cc0 Torch -[freeBlockCreationDataA]',
        selectors={
                 0x4b5cb8: (15192448, 'getSaveDict'),
        },
        imports={
                 0x4b5cb4: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(4938868, 'push {fp, lr}'), (4938940, 'adcseq sb, sl, r8, ror 28')],
        calls=[(4938920, 'blx r3')],
        branches=[],
        semantics=('[Torch freeBlockCreationSaveDict] (imp 0x004b5c74, 19w): thin forwarder via ffffbcac + ffe1d68c.\n'),
    ),
    dict(
        name='t_fbdataa',
        method='Torch -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=4938944,
        end=4939064,
        disasm='disasm_worldtileloader_t_fbdataa.txt',
        base_add=4938952,
        base_literal=4939000,
        boundary='ARM.exidx end 0x004b5d38 (listing bound); next ObjC IMP 0x004b5cfc Torch -[freeBlockCreationDataB]',
        selectors={},
        imports={},
        ivars={
                 0x4b5cf4: (17154972, 'OBJC_IVAR_$_Torch.dataA', 80),
                 0x4b5d30: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
        },
        classes={},
        instructions=[(4938944, 'sub sp, sp, 8'), (4939060, 'adcseq sb, sl, r8, ror 27')],
        calls=[],
        branches=[],
        semantics=('[Torch freeBlockCreationDataA] (imp 0x004b5cc0, 30w): **halfword** read (ldrh) through the ffffc8a8 cell - the torch stores dataA as a u16.\n'),
    ),
    dict(
        name='t_fbdatab',
        method='Torch -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=4939004,
        end=4939064,
        disasm='disasm_worldtileloader_t_fbdatab.txt',
        base_add=4939012,
        base_literal=4939060,
        boundary='ARM.exidx end 0x004b5d38 (listing bound); next ObjC IMP 0x004b5d38 Torch -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={},
        imports={},
        ivars={
                 0x4b5d30: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
        },
        classes={},
        instructions=[(4939004, 'sub sp, sp, 8'), (4939060, 'adcseq sb, sl, r8, ror 27')],
        calls=[],
        branches=[],
        semantics=('[Torch freeBlockCreationDataB] (imp 0x004b5cfc, 15w): halfword read through the ffffc8a4 cell.\n'),
    ),
    dict(
        name='t_ctor_save',
        method='Torch -[initWithWorld:dynamicWorld:saveDict:cache:]',
        types='@24@0:4@8@12@16@20',
        start=4939064,
        end=4940336,
        disasm='disasm_worldtileloader_t_ctor_save.txt',
        base_add=4939080,
        base_literal=4940332,
        boundary='ARM.exidx end 0x004b6230 (listing bound); next ObjC IMP 0x004b6230 Torch -[initWithWorld:dynamicWorld:cache:netData:]',
        selectors={
                 0x4b61c8: (15192452, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0x4b61dc: (15192424, 'retain'),
                 0x4b61e4: (15192428, 'objectForKey:'),
                 0x4b61ec: (15192456, 'intValue'),
                 0x4b620c: (15192460, 'initWithWorld:dynamicWorld:saveDict:cache:parentObject:'),
                 0x4b6220: (15192436, 'alloc'),
                 0x4b6228: (15192444, 'initSubDerivedItems'),
        },
        imports={
                 0x4b61c4: (17151900, 'objc_msgSendSuper2'),
                 0x4b61d8: (17151904, 'objc_msgSend'),
                 0x4b61e0: (16200824, '__CFConstantStringClassReference'),
                 0x4b61f0: (16200888, '__CFConstantStringClassReference'),
                 0x4b61f8: (16200872, '__CFConstantStringClassReference'),
                 0x4b61fc: (16200856, '__CFConstantStringClassReference'),
                 0x4b6204: (16200840, '__CFConstantStringClassReference'),
                 0x4b6214: (16200904, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x4b61d0: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4b61d4: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x4b61e8: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
                 0x4b61f4: (17154972, 'OBJC_IVAR_$_Torch.dataA', 80),
                 0x4b6200: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
                 0x4b6208: (17154980, 'OBJC_IVAR_$_Torch.light', 56),
                 0x4b6210: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x4b6218: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4b621c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0x4b61cc: (15252524, 'OBJC_CLASS_$_Torch'),
                 0x4b6224: (15244944, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(4939064, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4939216, 'blx r6'), (4939300, 'ldr r4, [0x004b61e0]'), (4939372, 'add r0, r0, r1'), (4940332, 'adcseq sb, sl, r4, lsr 27')],
        calls=[(4939216, 'blx r6'), (4939496, 'blx r5'), (4939512, 'blx r2'), (4939556, 'blx r3'), (4939572, 'blx r2'), (4939616, 'blx r3'), (4939632, 'blx r2'), (4939676, 'blx r3'), (4939692, 'blx r2'), (4939736, 'blx r3'), (4939752, 'blx r2'), (4939952, 'blx r2'), (4940040, 'blx r4'), (4940140, 'blx r7'), (4940204, 'blx r2')],
        branches=[(4939244, 'bne', 4939260), (4939256, 'b', 4940216), (4939800, 'beq', 4940164)],
        semantics=("[Torch initWithWorld:dynamicWorld:saveDict:cache:] (imp 0x004b5d38, 318w): the save-dict ctor - super2-shaped blx (@0x4b5dd0) + nil gate (@0x4b5dec); binds the **save-key pool fff13984/f13994/f139a4/f139b4/f139c4** (the torch's save-dict keys @0x4b5e24-0x4b5e6c) around the ffffc88c/c8ac/a4/a8/c8bc ivar cells + ffffbca8/bcac + ffe1d670/d678/d690/d694; the decode chain fills dataA/dataB/type from the dict.\n"),
    ),
    dict(
        name='t_ctor_net',
        method='Torch -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=4940336,
        end=4941204,
        disasm='disasm_worldtileloader_t_ctor_net.txt',
        base_add=4940352,
        base_literal=4941200,
        boundary='ARM.exidx end 0x004b6594 (listing bound); next ObjC IMP 0x004b65b8 Torch -[getSaveDict]',
        selectors={
                 0x4b654c: (15192464, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x4b6558: (15192472, 'length'),
                 0x4b656c: (15192468, 'getBytes:length:'),
                 0x4b6574: (15192424, 'retain'),
                 0x4b657c: (15192428, 'objectForKey:'),
                 0x4b6580: (15192480, 'gzipInflate'),
                 0x4b6588: (15192476, 'subdataWithRange:'),
                 0x4b658c: (15192444, 'initSubDerivedItems'),
        },
        imports={
                 0x4b6548: (17151900, 'objc_msgSendSuper2'),
                 0x4b6554: (17151904, 'objc_msgSend'),
                 0x4b6578: (16200824, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x4b655c: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
                 0x4b6560: (17154972, 'OBJC_IVAR_$_Torch.dataA', 80),
                 0x4b6564: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4b6568: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
                 0x4b6570: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0x4b6550: (15252524, 'OBJC_CLASS_$_Torch'),
        },
        instructions=[(4940336, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4940488, 'blx r6'), (4940588, 'movw r6, 0x20'), (4941200, 'adcseq sb, sl, ip, lsr 17')],
        calls=[(4940488, 'blx r6'), (4940656, 'blx r6'), (4940772, 'blx r4'), (4940844, 'bl loc.imp.objc_msgSend'), (4940912, 'bl loc.imp.objc_msgSend'), (4940936, 'blx r2'), (4940940, 'bl 0x4b6594'), (4941024, 'blx r3'), (4941040, 'blx r2'), (4941104, 'blx r2')],
        branches=[(4940516, 'bne', 4940532), (4940528, 'b', 4941116), (4940780, 'bls', 4941064)],
        semantics=('[Torch initWithWorld:dynamicWorld:cache:netData:] (imp 0x004b6230, 217w): the net ctor - blx via ffffbca8 (@0x4b62c8) + nil gate; reads a **0x20 (32)-byte record** (`movw r6, 0x20` @0x4b632c) into the fp frame then fills the ffffc8a4/c8a8/c88c/c8bc ivars + ffe1d69c/d6a0/d6a4.\n'),
    ),
    dict(
        name='t_getsavedict',
        method='Torch -[getSaveDict]',
        types='@8@0:4',
        start=4941240,
        end=4942304,
        disasm='disasm_worldtileloader_t_getsavedict.txt',
        base_add=4941256,
        base_literal=4942300,
        boundary='ARM.exidx end 0x004b69e0 (listing bound); next ObjC IMP 0x004b69e0 Torch -[updateNetDataForClient:]',
        selectors={
                 0x4b6994: (15192448, 'getSaveDict'),
                 0x4b69a8: (15192488, 'setObject:forKey:'),
                 0x4b69ac: (15192484, 'numberWithInt:'),
        },
        imports={
                 0x4b6990: (17151900, 'objc_msgSendSuper2'),
                 0x4b699c: (17151904, 'objc_msgSend'),
                 0x4b69a4: (16200840, '__CFConstantStringClassReference'),
                 0x4b69b8: (16200888, '__CFConstantStringClassReference'),
                 0x4b69c0: (16200872, '__CFConstantStringClassReference'),
                 0x4b69c8: (16200856, '__CFConstantStringClassReference'),
                 0x4b69d0: (16200904, '__CFConstantStringClassReference'),
                 0x4b69d8: (16200824, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x4b69a0: (17154980, 'OBJC_IVAR_$_Torch.light', 56),
                 0x4b69b0: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
                 0x4b69bc: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
                 0x4b69c4: (17154972, 'OBJC_IVAR_$_Torch.dataA', 80),
                 0x4b69cc: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4b69d4: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0x4b6998: (15252524, 'OBJC_CLASS_$_Torch'),
                 0x4b69b4: (15244948, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(4941240, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4941324, 'blx ip'), (4941456, 'add r1, r1, r0'), (4942300, 'adcseq sb, sl, r4, lsr 10')],
        calls=[(4941324, 'blx ip'), (4941632, 'blx r3'), (4941668, 'blx ip'), (4941728, 'blx r3'), (4941764, 'blx ip'), (4941824, 'blx r3'), (4941860, 'blx ip'), (4941920, 'blx r3'), (4941956, 'blx ip'), (4941992, 'blx r3'), (4942080, 'blx ip'), (4942208, 'blx ip')],
        branches=[(4942012, 'beq', 4942084), (4942120, 'beq', 4942212)],
        semantics=('[Torch getSaveDict] (imp 0x004b65b8, 266w): the reverse save chain - super call via ffffbca8 (@0x4b660c), then the key-pool stores **fff13994/f139c4/f139b4/f139a4** (@0x4b6638-0x4b66b0) wrap the ffffc8b0/c8bc/c8a4/c8a8/c88c ivar reads into the returned dict; the ffe1d68c/83a0/8bb4 call chain builds the dict.\n'),
    ),
    dict(
        name='t_updatenet',
        method='Torch -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=4942304,
        end=4942388,
        disasm='disasm_worldtileloader_t_updatenet.txt',
        base_add=4942320,
        base_literal=4942384,
        boundary='ARM.exidx end 0x004b6a34 (listing bound); next ObjC IMP 0x004b6a34 Torch -[creationNetDataForClient:]',
        selectors={
                 0x4b6a2c: (15192492, 'creationNetDataForClient:'),
        },
        imports={
                 0x4b6a28: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(4942304, 'push {fp, lr}'), (4942384, 'ldrshteq sb, [sl], ip')],
        calls=[(4942364, 'blx ip')],
        branches=[],
        semantics=('[Torch updateNetDataForClient:] (imp 0x004b69e0, 21w): thin forwarder via ffffbcac + ffe1d6b8.\n'),
    ),
    dict(
        name='t_creationdata',
        method='Torch -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=4942388,
        end=4943204,
        disasm='disasm_worldtileloader_t_creationdata.txt',
        base_add=4942404,
        base_literal=4943200,
        boundary='ARM.exidx end 0x004b6d64 (listing bound); next ObjC IMP 0x004b6ed0 Torch -[dealloc]',
        selectors={
                 0x4b6d24: (15192496, 'dynamicObjectNetData'),
                 0x4b6d30: (15192504, 'dictionary'),
                 0x4b6d38: (15192500, 'dataWithBytes:length:'),
                 0x4b6d54: (15192488, 'setObject:forKey:'),
                 0x4b6d58: (15192512, 'appendData:'),
                 0x4b6d5c: (15192508, 'gzipDeflate'),
        },
        imports={
                 0x4b6d2c: (17151904, 'objc_msgSend'),
                 0x4b6d50: (16200824, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x4b6d28: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x4b6d40: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
                 0x4b6d44: (17154972, 'OBJC_IVAR_$_Torch.dataA', 80),
                 0x4b6d48: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4b6d4c: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
        },
        classes={
                 0x4b6d34: (15244956, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x4b6d3c: (15244952, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(4942388, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4942516, 'bl sym.imp.memset'), (4942564, 'movw r5, 0x20'), (4943200, 'adcseq sb, sl, r8, lsr 1')],
        calls=[(4942480, 'bl loc.imp.objc_msgSend_stret'), (4942516, 'bl sym.imp.memset'), (4942732, 'bl sym.imp.memcpy'), (4942868, 'blx lr'), (4942904, 'blx r3'), (4943028, 'blx ip'), (4943036, 'bl 0x4b6d64'), (4943096, 'blx lr'), (4943124, 'blx r3')],
        branches=[(4942464, 'beq', 4942488), (4942484, 'b', 4942520), (4942940, 'beq', 4943032)],
        semantics=('[Torch creationNetDataForClient:] (imp 0x004b6a34, 204w): nil path zero-fills a **0x18 (24)-byte stret** (memset @0x4b6ab4); the live path reads the ffffc8ac/bcac/c8a4/c8a8 ivars and packs the **0x20-byte record** (`movw r5, 0x20` @0x4b6ae4) through ffe2a3a4/a3a8 + ffe1d6c0/c4.\n'),
    ),
    dict(
        name='t_dealloc',
        method='Torch -[dealloc]',
        types='v8@0:4',
        start=4943568,
        end=4943860,
        disasm='disasm_worldtileloader_t_dealloc.txt',
        base_add=4943584,
        base_literal=4943856,
        boundary='ARM.exidx end 0x004b6ff4 (listing bound); next ObjC IMP 0x004b6ff4 Torch -[removeFromMacroBlock]',
        selectors={
                 0x4b6fd8: (15192520, 'dealloc'),
                 0x4b6fe4: (15192516, 'release'),
        },
        imports={
                 0x4b6fd4: (17151900, 'objc_msgSendSuper2'),
                 0x4b6fe0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4b6fe8: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x4b6fec: (17154980, 'OBJC_IVAR_$_Torch.light', 56),
        },
        classes={
                 0x4b6fdc: (15252524, 'OBJC_CLASS_$_Torch'),
        },
        instructions=[(4943568, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4943816, 'blx r2'), (4943856, 'adcseq r8, sl, ip, lsl 24')],
        calls=[(4943716, 'blx r5'), (4943776, 'blx lr'), (4943816, 'blx r2')],
        branches=[],
        semantics=('[Torch dealloc] (imp 0x004b6ed0, 73w): the teardown chain - ffffbca8/bcac/c8ac/c8b0 + ffe1d6d0/d6d4, super dealloc (@0x4b6fc8).\n'),
    ),
    dict(
        name='t_rmmacro',
        method='Torch -[removeFromMacroBlock]',
        types='v8@0:4',
        start=4943860,
        end=4944344,
        disasm='disasm_worldtileloader_t_rmmacro.txt',
        base_add=4943876,
        base_literal=4944336,
        boundary='ARM.exidx end 0x004b71d8 (listing bound); next ObjC IMP 0x004b71d8 Torch -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x4b71b0: (15192524, 'removeFromMacroBlock'),
                 0x4b71c0: (15192516, 'release'),
                 0x4b71cc: (15192416, 'macroTiles'),
        },
        imports={
                 0x4b71ac: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x4b71b8: (17154980, 'OBJC_IVAR_$_Torch.light', 56),
                 0x4b71c4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4b71c8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0x4b71b4: (15252524, 'OBJC_CLASS_$_Torch'),
        },
        instructions=[(4943860, 'push {fp, lr}'), (4943992, 'str r3, [r0, r2]'), (4944116, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (4944340, 'andeq r0, r0, r0')],
        calls=[(4943940, 'bl loc.imp.objc_msgSend'), (4943972, 'bl loc.imp.objc_msgSend'), (4944072, 'bl loc.imp.objc_msgSend'), (4944116, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (4944176, 'bl loc.imp.objc_msgSend'), (4944220, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (4944288, 'blx r3')],
        branches=[],
        semantics=("[Torch removeFromMacroBlock] (imp 0x004b6ff4, 121w): the removal path calls **`reloadDrawBlockDynamicObjectQuadsForTile(intpair, MacroTile*, World*)`** (@0x4b70f4) - the dynamic-object quad reload; the same C-symbol family as the GlowBlock's `reloadDrawBlockLightGlowQuadsForTile` (E68): removing the torch invalidates its tile's dynamic-object quads. The ffffc89c/c8a0 cells + ffe1d6d0/d6d8 chains locate the tile; a zero store clears the ivar (@0x4b7078).\n"),
    ),
    dict(
        name='t_draw',
        method='Torch -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=4944344,
        end=4945872,
        disasm='disasm_worldtileloader_t_draw.txt',
        base_add=4944364,
        base_literal=4945868,
        boundary='ARM.exidx end 0x004b77d0 (listing bound); next ObjC IMP 0x004b77d0 Torch -[remoteUpdate:]',
        selectors={
                 0x4b77c4: (15192528, 'renderImageIndex'),
        },
        imports={
                 0x4b77c0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4b77a8: (17154952, 'OBJC_IVAR_$_Torch.animates', 76),
                 0x4b77ac: (17154996, 'OBJC_IVAR_$_Torch.savedDrawBuffer', 84),
                 0x4b77b0: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0x4b77b4: (17155004, 'OBJC_IVAR_$_Torch.savedDrawBufferIndex', 88),
                 0x4b77b8: (17155008, 'OBJC_IVAR_$_Torch.animationLoopTimer', 72),
                 0x4b77c8: (17155012, 'OBJC_IVAR_$_Torch.animationLoopIndex', 68),
        },
        classes={},
        instructions=[(4944344, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4944356, 'bic sp, sp, 0xf'), (4944932, 'ldrsb r0, [r0]'), (4945072, 'ldr r2, [r2, 0x1a4]'), (4945092, 'cmp r2, r0'), (4945868, 'adcseq r8, sl, r0, lsl 18')],
        calls=[(4945504, 'blx ip'), (4945520, 'bl sym.imp.__modsi3'), (4945536, 'bl sym.imp.__aeabi_idiv'), (4945752, 'bl sym.updateQuadBufferTexCoords_float__int__float__float__float__float_')],
        branches=[(4944944, 'beq', 4945796), (4944984, 'beq', 4945796), (4945028, 'beq', 4945760), (4945096, 'bne', 4945760), (4945164, 'ble', 4945760), (4945256, 'ble', 4945404), (4945360, 'blt', 4945400), (4945400, 'b', 4945216), (4945412, 'beq', 4945756), (4945756, 'b', 4945792), (4945792, 'b', 4945796)],
        semantics=('[Torch draw:...] (imp 0x004b71d8, 382w): the 16-byte-aligned marshalling frame (`bic sp, sp, 0xf` @0x4b71e4) + the visibility gates: the ffffc894 flag (`ldrsb; cmp 0; beq` @0x4b7424 exits) then the ffffc8c0/c8c4 ivar chains and the **field+0x1a4** read (`ldr r2, [r2, 0x1a4]` @0x4b74b0) compared against the cell value (@0x4b74c4) decide the draw; the branches pass the fp-marshalled camera/matrix args to the draw emit. Same visibility structure as the E25/E41 draw passes.\n'),
    ),
    dict(
        name='t_remoteupdate',
        method='Torch -[remoteUpdate:]',
        types='v12@0:4@8',
        start=4945872,
        end=4946108,
        disasm='disasm_worldtileloader_t_remoteupdate.txt',
        base_add=4945888,
        base_literal=4946104,
        boundary='ARM.exidx end 0x004b78bc (listing bound); next ObjC IMP 0x004b78bc Torch -[waterContentChanged:]',
        selectors={
                 0x4b78a4: (15192532, 'remoteUpdate:'),
                 0x4b78b4: (15192468, 'getBytes:length:'),
        },
        imports={
                 0x4b78a0: (17151900, 'objc_msgSendSuper2'),
                 0x4b78b0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4b78ac: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
        },
        classes={
                 0x4b78a8: (15252524, 'OBJC_CLASS_$_Torch'),
        },
        instructions=[(4945872, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4945928, 'movw r7, 0x20'), (4946004, 'ldrsb r0, [sp, 0x3e]'), (4946104, 'adcseq r8, sl, ip, lsl 6')],
        calls=[(4946000, 'blx r8'), (4946068, 'blx r3')],
        branches=[],
        semantics=('[Torch remoteUpdate:] (imp 0x004b77d0, 59w): the ffffc8bc/bcac cells + the **0x20-record decode** (`movw r7, 0x20` @0x4b7808, blx r8 @0x4b7850) then `ldrsb [sp, 0x3e]` reads the decoded flag into the ivar (@0x4b7854-0x4b7868); ffe1d6a0/d6e0.\n'),
    ),
    dict(
        name='t_waterchanged',
        method='Torch -[waterContentChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=4946108,
        end=4946900,
        disasm='disasm_worldtileloader_t_waterchanged.txt',
        base_add=4946124,
        base_literal=4946896,
        boundary='ARM.exidx end 0x004b7bd4 (listing bound); next ObjC IMP 0x004b7bd4 Torch -[worldContentsChanged:]',
        selectors={
                 0x4b7ba4: (15192536, 'isClient'),
                 0x4b7bb8: (15192544, 'removeStandardObject:'),
                 0x4b7bc8: (15192448, 'getSaveDict'),
                 0x4b7bcc: (15192540, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x4b7ba0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4b7b98: (17154956, 'OBJC_IVAR_$_Torch.flatOnSideAndBottom', 77),
                 0x4b7b9c: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4b7ba8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4b7bac: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4b7bb0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4b7bb4: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x4b7bc0: (17154972, 'OBJC_IVAR_$_Torch.dataA', 80),
                 0x4b7bc4: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
        },
        classes={},
        instructions=[(4946108, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4946164, 'cmp r0, 0'), (4946208, 'beq 0x4b7b90'), (4946360, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4946896, 'adcseq r8, sl, r0, lsr 4')],
        calls=[(4946360, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4946428, 'blx r3'), (4946448, 'bl sym.tileIsWater_Tile_'), (4946688, 'bl loc.imp.objc_msgSend'), (4946780, 'bl loc.imp.objc_msgSend'), (4946820, 'blx ip')],
        branches=[(4946172, 'bne', 4946832), (4946208, 'beq', 4946832), (4946244, 'beq', 4946832), (4946284, 'beq', 4946832), (4946440, 'bne', 4946828), (4946460, 'beq', 4946828), (4946496, 'bne', 4946824), (4946824, 'b', 4946832), (4946828, 'b', 4946832)],
        semantics=("[Torch waterContentChanged:] (imp 0x004b78bc, 198w): the water reaction - the ffffc898 submerged flag gate (`ldrsb; cmp 0; bne` @0x4b78f4: already wet exits); then the block-type chain **0x96 / 0xfe / 0x102** (same fire-family constants as getLightRGB) exits for those types (@0x4b7920-0x4b796c); otherwise it locates the tile via ffffc8a0/c89c + **tileAtWorldPositionLoaded** (@0x4b79b8) and runs the ffffbcac/c8b4 + ffe1d6e4 reaction chain - the torch's block reacts to water (the fire family is quenched).\n"),
    ),
    dict(
        name='t_worldcontents',
        method='Torch -[worldContentsChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=4946900,
        end=4950864,
        disasm='disasm_worldtileloader_t_worldcontents.txt',
        base_add=4946916,
        base_literal=4950860,
        boundary='ARM.exidx end 0x004b8b50 (listing bound); next ObjC IMP 0x004b8b50 Torch -[worldChanged:]',
        selectors={
                 0x4b8b08: (15192536, 'isClient'),
                 0x4b8b14: (15192544, 'removeStandardObject:'),
                 0x4b8b28: (15192448, 'getSaveDict'),
                 0x4b8b2c: (15192540, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x4b8b40: (15192548, 'objectType'),
                 0x4b8b44: (15192552, 'dynamicWorldChangedAtPos:objectType:'),
                 0x4b8b48: (15192416, 'macroTiles'),
        },
        imports={
                 0x4b8b04: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4b8af0: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
                 0x4b8af4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4b8af8: (17154956, 'OBJC_IVAR_$_Torch.flatOnSideAndBottom', 77),
                 0x4b8afc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4b8b0c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4b8b10: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x4b8b1c: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4b8b20: (17154972, 'OBJC_IVAR_$_Torch.dataA', 80),
                 0x4b8b24: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
                 0x4b8b38: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(4946900, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4947596, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4947652, 'mvn r0, 1'), (4947808, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (4948040, 'cmp r0, 0x64'), (4948208, 'bl sym.tileContainsDoor_Tile_'), (4948400, 'mvn r0, 0'), (4948828, 'bl loc.imp.objc_msgSend'), (4950860, 'adcseq r7, sl, r8, lsl 30')],
        calls=[(4947596, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4947788, 'bl sym.makeIntpair_int__int_'), (4947808, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (4947936, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4947964, 'bl sym.tileIsSolid_Tile_'), (4948160, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4948188, 'bl sym.tileIsSolid_Tile_'), (4948208, 'bl sym.tileContainsDoor_Tile_'), (4948336, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4948364, 'bl sym.tileIsSolid_Tile_'), (4948384, 'bl sym.tileContainsDoor_Tile_'), (4948496, 'blx r2'), (4948736, 'bl loc.imp.objc_msgSend'), (4948828, 'bl loc.imp.objc_msgSend'), (4948868, 'blx ip'), (4948976, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4949004, 'bl sym.tileIsSolid_Tile_'), (4949196, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4949304, 'bl sym.makeIntpair_int__int_'), (4949324, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (4949452, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4949480, 'bl sym.tileIsSolid_Tile_'), (4949500, 'bl sym.tileContainsDoor_Tile_'), (4949628, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4949656, 'bl sym.tileIsSolid_Tile_'), (4949676, 'bl sym.tileContainsDoor_Tile_'), (4949872, 'blx r2'), (4950112, 'bl loc.imp.objc_msgSend'), (4950204, 'bl loc.imp.objc_msgSend'), (4950244, 'blx ip'), (4950468, 'bl loc.imp.objc_msgSend'), (4950504, 'bl loc.imp.objc_msgSend'), (4950576, 'bl loc.imp.objc_msgSend'), (4950620, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (4950680, 'bl loc.imp.objc_msgSend'), (4950724, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(4947200, 'beq', 4950344), (4947276, 'bge', 4950280), (4947320, 'ble', 4950280), (4947364, 'bge', 4947412), (4947408, 'bgt', 4947488), (4947448, 'ble', 4950280), (4947484, 'bne', 4950280), (4947520, 'beq', 4948900), (4947616, 'beq', 4947688), (4947632, 'beq', 4947688), (4947648, 'bne', 4947688), (4947684, 'b', 4948896), (4947700, 'beq', 4947860), (4947820, 'beq', 4947860), (4947856, 'b', 4948892), (4947956, 'beq', 4948016), (4947976, 'beq', 4948016), (4948012, 'b', 4948888), (4948028, 'beq', 4948084), (4948044, 'bne', 4948084), (4948080, 'b', 4948884), (4948180, 'beq', 4948260), (4948200, 'beq', 4948260), (4948220, 'bne', 4948260), (4948256, 'b', 4948880), (4948356, 'beq', 4948436), (4948376, 'beq', 4948436), (4948396, 'bne', 4948436), (4948432, 'b', 4948876), (4948508, 'bne', 4948872), (4948544, 'bne', 4948872), (4948872, 'b', 4948876), (4948876, 'b', 4948880), (4948880, 'b', 4948884), (4948884, 'b', 4948888), (4948888, 'b', 4948892), (4948892, 'b', 4948896), (4948896, 'b', 4950276), (4948996, 'beq', 4949056), (4949016, 'beq', 4949056), (4949052, 'b', 4950272), (4949068, 'beq', 4949124), (4949084, 'bne', 4949124), (4949120, 'b', 4950268), (4949216, 'beq', 4949376), (4949336, 'beq', 4949376), (4949372, 'b', 4950264), (4949472, 'beq', 4949552), (4949492, 'beq', 4949552), (4949512, 'bne', 4949552), (4949548, 'b', 4950260), (4949648, 'beq', 4949728), (4949668, 'beq', 4949728), (4949688, 'bne', 4949728), (4949724, 'b', 4950256), (4949740, 'beq', 4949812), (4949756, 'beq', 4949812), (4949772, 'bne', 4949812), (4949808, 'b', 4950252), (4949884, 'bne', 4950248), (4949920, 'bne', 4950248), (4950248, 'b', 4950252), (4950252, 'b', 4950256), (4950256, 'b', 4950260), (4950260, 'b', 4950264), (4950264, 'b', 4950268), (4950268, 'b', 4950272), (4950272, 'b', 4950276), (4950276, 'b', 4950344), (4950280, 'b', 4950284), (4950340, 'b', 4947048), (4950380, 'beq', 4950760)],
        semantics=("[Torch worldContentsChanged:] (imp 0x004b7bd4, 991w): the **light-placement solver**. The ±2 neighbourhood scan (`add r0, r0, 2` / `sub r0, r0, 2` / `cmn r0, 2` @0x4b7d44-0x4b7e1c) checks the neighbours; the ffffc898 water flag gates (@0x4b7e3c); then **tileAtWorldPositionLoaded** probes (@0x4b7e8c) classify the tiles and store a placement/orientation code through the ffffc8bc cell: **-2** (`mvn r0, 1` @0x4b7ec4: none), **2** (`tileIsHalfDepth` @0x4b7f60), **0** (`tileIsSolid` at y-1 @0x4b7ffc), **3** (tile byte **+0xb == 0x64 ('d')** @0x4b8048), **1** (solid + `tileContainsDoor` @0x4b80f0), **-1** (`mvn r0, 0` @0x4b81b0: the x-1 solid+door arm). If all arms fail the tail runs the objc bool gate (@0x4b8210) + the ffffc8d4 flag (`ldrsb` @0x4b8238) then the **torch-creation** call with the big frame (uxth dataA/dataB + record fields @0x4b833c-0x4b835c) - if no valid position exists the torch makes a new one (the spreading/relight).\n"),
    ),
    dict(
        name='t_worldchanged',
        method='Torch -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=4950864,
        end=4951016,
        disasm='disasm_worldtileloader_t_worldchanged.txt',
        base_add=4950880,
        base_literal=4951012,
        boundary='ARM.exidx end 0x004b8be8 (listing bound); next ObjC IMP 0x004b8be8 Torch -[setNeedsRemoved:]',
        selectors={
                 0x4b8bd8: (15192560, 'worldContentsChanged:'),
                 0x4b8bdc: (15192556, 'worldChanged:'),
        },
        imports={
                 0x4b8bd4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4b8be0: (17154980, 'OBJC_IVAR_$_Torch.light', 56),
        },
        classes={},
        instructions=[(4950864, 'push {r4, r5, fp, lr}'), (4950960, 'blx ip'), (4951012, 'adcseq r6, sl, ip, lsl 31')],
        calls=[(4950960, 'blx ip'), (4950984, 'blx r3')],
        branches=[],
        semantics=('[Torch worldChanged:] (imp 0x004b8b50, 38w): forwarder via ffffbcac/c8b0 + ffe1d6f8/f6fc (`blx ip` @0x4b8bb0).\n'),
    ),
    dict(
        name='t_setneedsremoved',
        method='Torch -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=4951016,
        end=4951248,
        disasm='disasm_worldtileloader_t_setneedsremoved.txt',
        base_add=4951032,
        base_literal=4951244,
        boundary='ARM.exidx end 0x004b8cd0 (listing bound); next ObjC IMP 0x004b8cd0 Torch -[renderImageIndex]',
        selectors={
                 0x4b8cb8: (15192564, 'setNeedsRemoved:'),
                 0x4b8cc4: (15192568, 'removeFromTiles'),
        },
        imports={
                 0x4b8cb4: (17151900, 'objc_msgSendSuper2'),
                 0x4b8cc0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4b8cc8: (17154980, 'OBJC_IVAR_$_Torch.light', 56),
        },
        classes={
                 0x4b8cbc: (15252524, 'OBJC_CLASS_$_Torch'),
        },
        instructions=[(4951016, 'push {r4, r5, fp, lr}'), (4951140, 'cmp r0, 0'), (4951208, 'blx r2'), (4951244, 'ldrshteq r6, [sl], r4')],
        calls=[(4951132, 'blx lr'), (4951208, 'blx r2')],
        branches=[(4951144, 'beq', 4951212)],
        semantics=('[Torch setNeedsRemoved:] (imp 0x004b8be8, 58w): sxtb flag gate (@0x4b8c64) then the ffffbcac/c8b0 + ffe1d700/d704 chain (`blx r2` @0x4b8ca8).\n'),
    ),
    dict(
        name='t_renderimageidx',
        method='Torch -[renderImageIndex]',
        types='i8@0:4',
        start=4951248,
        end=4951976,
        disasm='disasm_worldtileloader_t_renderimageidx.txt',
        base_add=4951256,
        base_literal=4951972,
        boundary='ARM.exidx end 0x004b8fa8 (listing bound); next ObjC IMP 0x004b8fa8 Torch -[staticGeometryDrawQuadCountForMacroPos:]',
        selectors={},
        imports={},
        ivars={
                 0x4b8f94: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4b8f9c: (17154952, 'OBJC_IVAR_$_Torch.animates', 76),
                 0x4b8fa0: (17155012, 'OBJC_IVAR_$_Torch.animationLoopIndex', 68),
        },
        classes={},
        instructions=[(4951248, 'sub sp, sp, 0x18'), (4951524, 'cmp r1, 0xc'), (4951556, 'andeq r0, r0, r8, rrx'), (4951972, 'adcseq r6, sl, r4, lsl lr')],
        calls=[],
        branches=[(4951316, 'bgt', 4951340), (4951320, 'b', 4951324), (4951332, 'beq', 4951792), (4951336, 'b', 4951864), (4951348, 'bgt', 4951372), (4951352, 'b', 4951356), (4951364, 'beq', 4951804), (4951368, 'b', 4951864), (4951380, 'bgt', 4951420), (4951384, 'b', 4951388), (4951396, 'beq', 4951768), (4951400, 'b', 4951404), (4951412, 'beq', 4951756), (4951416, 'b', 4951864), (4951428, 'bgt', 4951484), (4951432, 'b', 4951436), (4951444, 'beq', 4951744), (4951448, 'b', 4951452), (4951460, 'beq', 4951732), (4951464, 'b', 4951468), (4951476, 'beq', 4951780), (4951480, 'b', 4951864), (4951492, 'bgt', 4951624), (4951496, 'b', 4951500), (4951508, 'bgt', 4951608), (4951512, 'b', 4951516), (4951532, 'bhi', 4951864), (4951616, 'beq', 4951852), (4951620, 'b', 4951864), (4951632, 'beq', 4951828), (4951636, 'b', 4951640), (4951652, 'beq', 4951840), (4951656, 'b', 4951864), (4951668, 'b', 4951868), (4951680, 'b', 4951868), (4951692, 'b', 4951868), (4951704, 'b', 4951868), (4951716, 'b', 4951868), (4951728, 'b', 4951868), (4951740, 'b', 4951868), (4951752, 'b', 4951868), (4951764, 'b', 4951868), (4951776, 'b', 4951868), (4951788, 'b', 4951868), (4951800, 'b', 4951868), (4951812, 'b', 4951868), (4951824, 'b', 4951868), (4951836, 'b', 4951868), (4951848, 'b', 4951868), (4951860, 'b', 4951868), (4951864, 'b', 4951868), (4951900, 'beq', 4951944)],
        semantics=("[Torch renderImageIndex] (imp 0x004b8cd0, 182w): the block-type → sprite-index map as a **binary-compare cascade + 12-entry jump table**: compares 0x2e/0x11/0x4a/0x2f/0x55/'K'(0x4b)/'L'(0x4c)/0x90/'V'(0x56)/'W'(0x57)/'X'(0x58)/0xfd/0xb6 then `sub r1, r0, 0x91; cmp r1, 0xc; bhi` (@0x4b8de4-0x4b8dec) indexes the **12-word table at 0x4b8e04** - the render image for block types 0x91..0x9d (the torch-flame block family 145..157, matching the 0x9d glow-exception of lightGlowQuadCount).\n"),
    ),
    dict(
        name='t_staticquadcount',
        method='Torch -[staticGeometryDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=4951976,
        end=4952016,
        disasm='disasm_worldtileloader_t_staticquadcount.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004b8fd0 (listing bound); next ObjC IMP 0x004b8fd0 Torch -[addDrawQuadData:fromIndex:forMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(4951976, 'sub sp, sp, 0x10'), (4952012, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[Torch staticGeometryDrawQuadCountForMacroPos:] (imp 0x004b8fa8, 10w): returns **1** (movw ip, 1) - one static quad per macro pos.\n'),
    ),
    dict(
        name='t_adddrawquad',
        method='Torch -[addDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=4952016,
        end=4971064,
        disasm='disasm_worldtileloader_t_adddrawquad.txt',
        base_add=4952052,
        base_literal=4955676,
        boundary='ARM.exidx end 0x004bda38 (listing bound); next ObjC IMP 0x004be0d4 Torch -[lightPos]',
        selectors={
                 0x4bda18: (15192528, 'renderImageIndex'),
        },
        imports={
                 0x4bda14: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4b9e20: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x4b9e24: (17154948, 'OBJC_IVAR_$_Torch.chandelier', 78),
                 0x4b9e28: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4b9e2c: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
                 0x4ba1fc: (17154956, 'OBJC_IVAR_$_Torch.flatOnSideAndBottom', 77),
                 0x4bbdc0: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
                 0x4bc304: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4bda08: (17154948, 'OBJC_IVAR_$_Torch.chandelier', 78),
                 0x4bda0c: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4bda10: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
                 0x4bda1c: (17155004, 'OBJC_IVAR_$_Torch.savedDrawBufferIndex', 88),
                 0x4bda20: (17154996, 'OBJC_IVAR_$_Torch.savedDrawBuffer', 84),
                 0x4bda24: (17154952, 'OBJC_IVAR_$_Torch.animates', 76),
                 0x4bda2c: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0x4bda30: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
        },
        classes={},
        instructions=[(4952016, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4952024, 'sub sp, sp, 0x1800'), (4952208, 'movw r3, 0x6666'), (4952336, 'bne 0x4b92a8'), (4952740, 'bl sym.imp.memcpy'), (4953204, 'bl 0x4bdac0'), (4968916, 'bl sym.imp.memcpy'), (4971060, 'adcseq r2, sl, ip, lsr 11')],
        calls=[(4952148, 'bl method.Vector2.operator_float__'), (4952176, 'bl method.Vector2.operator_float__'), (4952216, 'bl 0x4bda38'), (4952704, 'bl 0x4bdac0'), (4952740, 'bl sym.imp.memcpy'), (4953204, 'bl 0x4bdac0'), (4953704, 'bl 0x4bdca8'), (4953740, 'bl sym.imp.memcpy'), (4954156, 'bl 0x4bdac0'), (4954660, 'bl 0x4bdca8'), (4954696, 'bl sym.imp.memcpy'), (4955108, 'bl 0x4bdac0'), (4955632, 'bl 0x4bdca8'), (4955668, 'bl sym.imp.memcpy'), (4956100, 'bl 0x4bdac0'), (4956624, 'bl 0x4bdca8'), (4956660, 'bl sym.imp.memcpy'), (4957068, 'bl 0x4bdac0'), (4957104, 'bl sym.imp.memcpy'), (4957516, 'bl 0x4bdac0'), (4957552, 'bl sym.imp.memcpy'), (4958020, 'bl 0x4bdac0'), (4958056, 'bl sym.imp.memcpy'), (4958468, 'bl 0x4bdac0'), (4958976, 'bl 0x4bdca8'), (4959012, 'bl sym.imp.memcpy'), (4959432, 'bl 0x4bdac0'), (4959936, 'bl 0x4bdca8'), (4959968, 'bl sym.imp.memcpy'), (4960384, 'bl 0x4bdac0'), (4960888, 'bl 0x4bdca8'), (4960920, 'bl sym.imp.memcpy'), (4961336, 'bl 0x4bdac0'), (4961840, 'bl 0x4bdca8'), (4961872, 'bl sym.imp.memcpy'), (4962396, 'bl 0x4bdac0'), (4962428, 'bl sym.imp.memcpy'), (4962840, 'bl 0x4bdac0'), (4962872, 'bl sym.imp.memcpy'), (4963288, 'bl 0x4bdac0'), (4963320, 'bl sym.imp.memcpy'), (4963736, 'bl 0x4bdac0'), (4963768, 'bl sym.imp.memcpy'), (4964180, 'bl 0x4bdac0'), (4964212, 'bl sym.imp.memcpy'), (4964628, 'bl 0x4bdac0'), (4964660, 'bl sym.imp.memcpy'), (4965084, 'bl 0x4bdac0'), (4965116, 'bl sym.imp.memcpy'), (4965524, 'bl 0x4bdac0'), (4966028, 'bl 0x4bdca8'), (4966060, 'bl sym.imp.memcpy'), (4966468, 'bl 0x4bdac0'), (4966972, 'bl 0x4bdca8'), (4967004, 'bl sym.imp.memcpy'), (4967428, 'bl 0x4bdac0'), (4967932, 'bl 0x4bdca8'), (4967964, 'bl sym.imp.memcpy'), (4968380, 'bl 0x4bdac0'), (4968884, 'bl 0x4bdca8'), (4968916, 'bl sym.imp.memcpy'), (4969012, 'blx r2'), (4969200, 'bl sym.imp.__modsi3'), (4969220, 'bl sym.imp.__aeabi_idiv'), (4969580, 'bl sym.clamp_float__float__float_'), (4970168, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (4970888, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_')],
        branches=[(4952256, 'bne', 4952300), (4952296, 'bne', 4952748), (4952336, 'bne', 4952744), (4952744, 'b', 4968952), (4952784, 'beq', 4957580), (4952824, 'bne', 4953748), (4953744, 'b', 4957576), (4953784, 'bne', 4954704), (4954700, 'b', 4957572), (4954740, 'bne', 4955696), (4955672, 'b', 4957568), (4955732, 'bne', 4956672), (4956664, 'b', 4957564), (4956708, 'bne', 4957112), (4957108, 'b', 4957560), (4957148, 'bne', 4957556), (4957556, 'b', 4957560), (4957560, 'b', 4957564), (4957564, 'b', 4957568), (4957568, 'b', 4957572), (4957572, 'b', 4957576), (4957576, 'b', 4968948), (4957616, 'bne', 4961896), (4957656, 'bne', 4958064), (4958060, 'b', 4961892), (4958100, 'bne', 4959020), (4959016, 'b', 4961888), (4959056, 'bne', 4959976), (4959972, 'b', 4961884), (4960012, 'bne', 4960928), (4960924, 'b', 4961880), (4960964, 'bne', 4961876), (4961876, 'b', 4961880), (4961880, 'b', 4961884), (4961884, 'b', 4961888), (4961888, 'b', 4961892), (4961892, 'b', 4968944), (4961932, 'beq', 4961980), (4961976, 'bne', 4964688), (4962016, 'bne', 4962436), (4962432, 'b', 4964684), (4962472, 'bne', 4962880), (4962876, 'b', 4964680), (4962916, 'bne', 4963328), (4963324, 'b', 4964676), (4963364, 'bne', 4963780), (4963772, 'b', 4964672), (4963816, 'bne', 4964220), (4964216, 'b', 4964668), (4964256, 'bne', 4964664), (4964664, 'b', 4964668), (4964668, 'b', 4964672), (4964672, 'b', 4964676), (4964676, 'b', 4964680), (4964680, 'b', 4964684), (4964684, 'b', 4968940), (4964724, 'bne', 4965128), (4965120, 'b', 4968936), (4965164, 'bne', 4966068), (4966064, 'b', 4968932), (4966104, 'bne', 4967012), (4967008, 'b', 4968928), (4967048, 'bne', 4967972), (4967968, 'b', 4968924), (4968008, 'bne', 4968920), (4968920, 'b', 4968924), (4968924, 'b', 4968928), (4968928, 'b', 4968932), (4968932, 'b', 4968936), (4968936, 'b', 4968940), (4968940, 'b', 4968944), (4968944, 'b', 4968948), (4968948, 'b', 4968952), (4969052, 'bne', 4969096), (4969092, 'bne', 4970184), (4969416, 'bne', 4969620), (4969420, 'b', 4969464), (4970172, 'b', 4970956)],
        semantics=("[Torch addDrawQuadData:fromIndex:forMacroPos:] (imp 0x004b8fd0, 4762w): the torch's **quad emitter** - a 0x1800-byte 16-byte-aligned frame (`sub sp, 0x1800; bic sp, sp, 0xf` @0x4b8fd8) with working areas at +0x400/+0x1000; the Vector2::operator float*() marshalling; the **-0.9f (0xbf666666)** and **-0.05f (0xbd4ccccd)** constants; the placement-code gates (==3 @0x4b9110, ==0 @0x4b92f4, the water flag @0x4b92d0) pick arms; each arm builds a 64-byte quad record (helper `bl 0x4bdac0` then **memcpy 0x40** into the buffer). Structural census: **23× bl 0x4bdac0 + 23× memcpy** (the quad arms), **12× bl 0x4bdca8** (the second helper), and **2× `fillQuadBuffer(float*, int, _GLKMatrix4*, float×8, int, int)`** (@the emit tail - the same fillQuadBuffer family of the E41/E44 draw passes); `clamp_float(float, float, float)`, `__modsi3`, `__aeabi_idiv` for the frame/edge math; float constants **-1.4125f (0xbfb4f4ab), ±0.48f (0x3ef5c28f/bef5c28f), ±0.1f, ±0.3f, ±0.4f, -0.7f (0xbf333333)** - the torch flame geometry. The double-buffer record swap (0x1e8..0x1f8 → 0x178.., 0x200.. → 0x180.., 0x218.. → 0x198.. @0x4b9118-0x4b9194) alternates the two emit states.\n"),
    ),
    dict(
        name='t_lightpos',
        method='Torch -[lightPos]',
        types='{Vector=[4f]}8@0:4',
        start=4972756,
        end=4975968,
        disasm='disasm_worldtileloader_t_lightpos.txt',
        base_add=4972772,
        base_literal=4975964,
        boundary='ARM.exidx end 0x004bed60 (listing bound); next ObjC IMP 0x004bed90 Torch -[lightGlowQuadCount]',
        selectors={},
        imports={},
        ivars={
                 0x4bed38: (17154948, 'OBJC_IVAR_$_Torch.chandelier', 78),
                 0x4bed3c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x4bed40: (17154956, 'OBJC_IVAR_$_Torch.flatOnSideAndBottom', 77),
                 0x4bed44: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4bed48: (17154992, 'OBJC_IVAR_$_Torch.connectionType', 60),
        },
        classes={},
        instructions=[(4972756, 'push {fp, lr}'), (4972964, 'cmp r0, 0'), (4973124, 'bne 0x4be290'), (4973232, 'bne 0x4be2fc'), (4973340, 'bne 0x4be360'), (4975964, 'adcseq r1, sl, r8, lsl 20')],
        calls=[(4972792, 'bl method.Vector.Vector__'), (4972828, 'bl method.Vector2.operator_float__'), (4972844, 'bl method.Vector.operator_float__'), (4972880, 'bl method.Vector2.operator_float__'), (4972904, 'bl method.Vector.operator_float__'), (4972920, 'bl method.Vector.operator_float__'), (4973000, 'bl method.Vector2.operator_float__'), (4973024, 'bl method.Vector.operator_float__'), (4973040, 'bl method.Vector.operator_float__'), (4973152, 'bl method.Vector2.operator_float__'), (4973168, 'bl method.Vector.operator_float__'), (4973184, 'bl method.Vector.operator_float__'), (4973260, 'bl method.Vector2.operator_float__'), (4973276, 'bl method.Vector.operator_float__'), (4973292, 'bl method.Vector.operator_float__'), (4973368, 'bl method.Vector2.operator_float__'), (4973392, 'bl method.Vector.operator_float__'), (4973468, 'bl method.Vector2.operator_float__'), (4973492, 'bl method.Vector.operator_float__'), (4973588, 'bl method.Vector.operator_float__'), (4973692, 'bl method.Vector2.operator_float__'), (4973716, 'bl method.Vector.operator_float__'), (4973768, 'bl method.Vector.operator_float__'), (4973844, 'bl method.Vector2.operator_float__'), (4973868, 'bl method.Vector.operator_float__'), (4973944, 'bl method.Vector2.operator_float__'), (4973968, 'bl method.Vector.operator_float__'), (4974068, 'bl method.Vector.operator_float__'), (4974208, 'bl method.Vector2.operator_float__'), (4974232, 'bl method.Vector.operator_float__'), (4974284, 'bl method.Vector.operator_float__'), (4974368, 'bl method.Vector2.operator_float__'), (4974392, 'bl method.Vector.operator_float__'), (4974468, 'bl method.Vector2.operator_float__'), (4974492, 'bl method.Vector.operator_float__'), (4974588, 'bl method.Vector.operator_float__'), (4974692, 'bl method.Vector2.operator_float__'), (4974716, 'bl method.Vector.operator_float__'), (4974768, 'bl method.Vector.operator_float__'), (4974844, 'bl method.Vector2.operator_float__'), (4974868, 'bl method.Vector.operator_float__'), (4974904, 'bl method.Vector2.operator_float__'), (4974928, 'bl method.Vector.operator_float__'), (4975004, 'bl method.Vector2.operator_float__'), (4975028, 'bl method.Vector.operator_float__'), (4975064, 'bl method.Vector2.operator_float__'), (4975088, 'bl method.Vector.operator_float__'), (4975184, 'bl method.Vector.operator_float__'), (4975248, 'bl method.Vector2.operator_float__'), (4975272, 'bl method.Vector.operator_float__'), (4975324, 'bl method.Vector.operator_float__'), (4975400, 'bl method.Vector2.operator_float__'), (4975424, 'bl method.Vector.operator_float__'), (4975460, 'bl method.Vector2.operator_float__'), (4975484, 'bl method.Vector.operator_float__'), (4975560, 'bl method.Vector2.operator_float__'), (4975584, 'bl method.Vector.operator_float__'), (4975620, 'bl method.Vector2.operator_float__'), (4975644, 'bl method.Vector.operator_float__'), (4975720, 'bl method.Vector2.operator_float__'), (4975744, 'bl method.Vector.operator_float__'), (4975824, 'bl method.Vector2.operator_float__'), (4975848, 'bl method.Vector.operator_float__'), (4975864, 'bl method.Vector.operator_float__')],
        branches=[(4972972, 'beq', 4973056), (4973052, 'b', 4975920), (4973088, 'beq', 4973632), (4973124, 'bne', 4973200), (4973196, 'b', 4973628), (4973232, 'bne', 4973308), (4973304, 'b', 4973624), (4973340, 'bne', 4973408), (4973404, 'b', 4973620), (4973440, 'bne', 4973508), (4973504, 'b', 4973616), (4973540, 'bne', 4973548), (4973544, 'b', 4973612), (4973580, 'bne', 4973608), (4973608, 'b', 4973612), (4973612, 'b', 4973616), (4973616, 'b', 4973620), (4973620, 'b', 4973624), (4973624, 'b', 4973628), (4973628, 'b', 4975916), (4973664, 'bne', 4974108), (4973760, 'bne', 4973784), (4973780, 'b', 4974104), (4973816, 'bne', 4973884), (4973880, 'b', 4974100), (4973916, 'bne', 4973984), (4973980, 'b', 4974096), (4974016, 'bne', 4974028), (4974020, 'b', 4974092), (4974060, 'bne', 4974088), (4974088, 'b', 4974092), (4974092, 'b', 4974096), (4974096, 'b', 4974100), (4974100, 'b', 4974104), (4974104, 'b', 4975912), (4974140, 'beq', 4974184), (4974180, 'bne', 4974632), (4974276, 'bne', 4974308), (4974296, 'b', 4974624), (4974340, 'bne', 4974408), (4974404, 'b', 4974620), (4974440, 'bne', 4974508), (4974504, 'b', 4974616), (4974540, 'bne', 4974548), (4974544, 'b', 4974612), (4974580, 'bne', 4974608), (4974608, 'b', 4974612), (4974612, 'b', 4974616), (4974616, 'b', 4974620), (4974620, 'b', 4974624), (4974624, 'b', 4975908), (4974664, 'bne', 4975224), (4974760, 'bne', 4974784), (4974780, 'b', 4975220), (4974816, 'bne', 4974944), (4974940, 'b', 4975216), (4974976, 'bne', 4975104), (4975100, 'b', 4975212), (4975136, 'bne', 4975144), (4975140, 'b', 4975208), (4975176, 'bne', 4975204), (4975204, 'b', 4975208), (4975208, 'b', 4975212), (4975212, 'b', 4975216), (4975216, 'b', 4975220), (4975220, 'b', 4975904), (4975316, 'bne', 4975340), (4975336, 'b', 4975900), (4975372, 'bne', 4975500), (4975496, 'b', 4975896), (4975532, 'bne', 4975660), (4975656, 'b', 4975892), (4975692, 'bne', 4975764), (4975756, 'b', 4975888), (4975796, 'bne', 4975884), (4975884, 'b', 4975888), (4975888, 'b', 4975892), (4975892, 'b', 4975896), (4975896, 'b', 4975900), (4975900, 'b', 4975904), (4975904, 'b', 4975908), (4975908, 'b', 4975912), (4975912, 'b', 4975916), (4975916, 'b', 4975920)],
        semantics=("[Torch lightPos] (imp 0x004be0d4, 803w): the **per-code light position selector** - `Vector::Vector()` + `Vector2::operator float*()` + vadd/vsub chains build the light's world position from the macro position (ffffc8dc) + a code-dependent offset: the ffffc890 flag arm (@0x4be1a4, the `mvn r3, 0` -1 initial), the ffffc898 water gate (@0x4be21c), then the placement-code cascade via ffffc8bc: code **0** (@0x4be244), **3** (@0x4be2b0), **1** (@0x4be31c, vadd arm), and the rest of the -2..3 family (@0x4be360+) each adding its own Vector offset (64 calls of the Vector/Vector2 ops).\n"),
    ),
    dict(
        name='t_glowquadcount',
        method='Torch -[lightGlowQuadCount]',
        types='i8@0:4',
        start=4976016,
        end=4976108,
        disasm='disasm_worldtileloader_t_glowquadcount.txt',
        base_add=4976024,
        base_literal=4976104,
        boundary='ARM.exidx end 0x004bedec (listing bound); next ObjC IMP 0x004bedec Torch -[isDownlight]',
        selectors={},
        imports={},
        ivars={
                 0x4bede4: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
        },
        classes={},
        instructions=[(4976016, 'sub sp, sp, 0xc'), (4976064, 'bne 0x4bedd0'), (4976104, 'adcseq r0, sl, r4, asr sp')],
        calls=[],
        branches=[(4976064, 'bne', 4976080), (4976076, 'b', 4976088)],
        semantics=('[Torch lightGlowQuadCount] (imp 0x004bed90, 23w): **block type 0x9d (157) → 0, else 1** (`cmp r0, 0x9d; bne` @0x4bedc0: the 0x9d block gets no light-glow quads - the glow-exception type).\n'),
    ),
    dict(
        name='t_isdownlight',
        method='Torch -[isDownlight]',
        types='c8@0:4',
        start=4976108,
        end=4976300,
        disasm='disasm_worldtileloader_t_isdownlight.txt',
        base_add=4976116,
        base_literal=4976184,
        boundary='ARM.exidx end 0x004beeac (listing bound); next ObjC IMP 0x004bee3c Torch -[isUplight]',
        selectors={},
        imports={},
        ivars={
                 0x4bee34: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
                 0x4bee88: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
        },
        classes={},
        instructions=[(4976108, 'sub sp, sp, 8'), (4976152, 'cmp r0, 0xfe'), (4976296, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Torch isDownlight] (imp 0x004bedec, 48w): **block type == 0xfe (254) → 1** (`cmp 0xfe; moveq 1` @0x4bee18).\n'),
    ),
    dict(
        name='t_isuplight',
        method='Torch -[isUplight]',
        types='c8@0:4',
        start=4976188,
        end=4976300,
        disasm='disasm_worldtileloader_t_isuplight.txt',
        base_add=4976196,
        base_literal=4976268,
        boundary='ARM.exidx end 0x004beeac (listing bound); next ObjC IMP 0x004bee90 Torch -[occupiesForegroundContents]',
        selectors={},
        imports={},
        ivars={
                 0x4bee88: (17154944, 'OBJC_IVAR_$_Torch.itemType', 64),
        },
        classes={},
        instructions=[(4976188, 'sub sp, sp, 8'), (4976236, 'cmp r0, r3'), (4976296, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Torch isUplight] (imp 0x004bee3c, 28w): **block type == 0x102 (258) → 1** (@0x4bee6c).\n'),
    ),
    dict(
        name='t_occupiesfg',
        method='Torch -[occupiesForegroundContents]',
        types='c8@0:4',
        start=4976272,
        end=4976300,
        disasm='disasm_worldtileloader_t_occupiesfg.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004beeac (listing bound); next ObjC IMP 0x004beeac Torch -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(4976272, 'sub sp, sp, 8'), (4976296, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Torch occupiesForegroundContents] (imp 0x004bee90, 7w): returns **1**.\n'),
    ),
    dict(
        name='t_addartistlightcont',
        method='Torch -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=4976300,
        end=4976416,
        disasm='disasm_worldtileloader_t_addartistlightcont.txt',
        base_add=4976316,
        base_literal=4976412,
        boundary='ARM.exidx end 0x004bef20 (listing bound); next ObjC IMP 0x004bef20 Torch -[dataA]',
        selectors={
                 0x4bef14: (15192572, 'addContributionForPhysicalBlockLoadedAtXPos:yPos:'),
        },
        imports={
                 0x4bef10: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4bef18: (17154980, 'OBJC_IVAR_$_Torch.light', 56),
        },
        classes={},
        instructions=[(4976300, 'push {r4, r5, fp, lr}'), (4976388, 'blx lr'), (4976412, 'adcseq r0, sl, r0, lsr ip')],
        calls=[(4976388, 'blx lr')],
        branches=[],
        semantics=('[Torch addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:] (imp 0x004beeac, 29w): thin via ffffbcac/c8b0 + ffe1d708 (`blx lr` @0x4bef04) - the torch registers its artificial-light contribution (the E68 ArtificialLight consumer).\n'),
    ),
    dict(
        name='t_dataa',
        method='Torch -[dataA]',
        types='S8@0:4',
        start=4976416,
        end=4976476,
        disasm='disasm_worldtileloader_t_dataa.txt',
        base_add=4976424,
        base_literal=4976472,
        boundary='ARM.exidx end 0x004bef5c (listing bound); next ObjC IMP 0x004bef5c Torch -[setDataA:]',
        selectors={},
        imports={},
        ivars={
                 0x4bef54: (17154972, 'OBJC_IVAR_$_Torch.dataA', 80),
        },
        classes={},
        instructions=[(4976416, 'sub sp, sp, 8'), (4976472, 'adcseq r0, sl, r4, asr 23')],
        calls=[],
        branches=[],
        semantics=('[Torch dataA] (imp 0x004bef20, 15w): **halfword read** (ldrh) via the ffffc8a8 cell.\n'),
    ),
    dict(
        name='t_setdataa',
        method='Torch -[setDataA:]',
        types='v12@0:4S8',
        start=4976476,
        end=4976548,
        disasm='disasm_worldtileloader_t_setdataa.txt',
        base_add=4976504,
        base_literal=4976544,
        boundary='ARM.exidx end 0x004befa4 (listing bound); next ObjC IMP 0x004befa4 Torch -[dataB]',
        selectors={},
        imports={},
        ivars={
                 0x4bef9c: (17154972, 'OBJC_IVAR_$_Torch.dataA', 80),
        },
        classes={},
        instructions=[(4976476, 'sub sp, sp, 0xc'), (4976520, 'dmb ish'), (4976528, 'dmb ish'), (4976544, 'adcseq r0, sl, r4, ror fp')],
        calls=[],
        branches=[],
        semantics=('[Torch setDataA:] (imp 0x004bef5c, 18w): the **`dmb ish`-fenced halfword store** - `strh r2, [sp, 2]` + `dmb ish; strh r2, [r0]; dmb ish` (@0x4bef88-0x4bef90): dataA is written atomically under SMP barriers (the same idiom as st3_setneedschoice).\n'),
    ),
    dict(
        name='t_datab',
        method='Torch -[dataB]',
        types='S8@0:4',
        start=4976548,
        end=4976608,
        disasm='disasm_worldtileloader_t_datab.txt',
        base_add=4976556,
        base_literal=4976604,
        boundary='ARM.exidx end 0x004befe0 (listing bound); next ObjC IMP 0x004befe0 Torch -[setDataB:]',
        selectors={},
        imports={},
        ivars={
                 0x4befd8: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
        },
        classes={},
        instructions=[(4976548, 'sub sp, sp, 8'), (4976604, 'adcseq r0, sl, r0, asr 22')],
        calls=[],
        branches=[],
        semantics=('[Torch dataB] (imp 0x004befa4, 15w): halfword read via the ffffc8a4 cell.\n'),
    ),
    dict(
        name='t_setdatab',
        method='Torch -[setDataB:]',
        types='v12@0:4S8',
        start=4976608,
        end=4976680,
        disasm='disasm_worldtileloader_t_setdatab.txt',
        base_add=4976636,
        base_literal=4976676,
        boundary='ARM.exidx end 0x004bf028 (listing bound); next ObjC IMP 0x004c0320 Tree -[removeFromMacroBlock]',
        selectors={},
        imports={},
        ivars={
                 0x4bf020: (17154968, 'OBJC_IVAR_$_Torch.dataB', 82),
        },
        classes={},
        instructions=[(4976608, 'sub sp, sp, 0xc'), (4976652, 'dmb ish'), (4976660, 'dmb ish'), (4976676, 'ldrshteq r0, [sl], r0')],
        calls=[],
        branches=[],
        semantics=('[Torch setDataB:] (imp 0x004befe0, 18w): the `dmb ish`-fenced halfword store via the ffffc8a4 cell (@0x4bf00c-0x4bf014).\n'),
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
        'batch': 'Torch class (E72): the primitive artificial light - the full 34-body class incl. getLightRGB, worldContentsChanged solver, addDrawQuadData emitter and lightPos; 34 bodies',
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
                        default=NATIVE / 'torch.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale torch.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
