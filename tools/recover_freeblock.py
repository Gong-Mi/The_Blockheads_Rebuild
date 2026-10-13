#!/usr/bin/env python3
"""Hash-gated recovery of the FreeBlock (E152).

FreeBlock lands: the batch sweeps freeblock surface:
31 bodies, 5938 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/FREEBLOCK.md for the prose and boundaries.
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
    'bl 0x625fd8': 0x00625fd8,
    'bl 0x628fdc': 0x00628fdc,
    'bl 0x62b0f4': 0x0062b0f4,
    'bl 0x63145c': 0x0063145c,
    'bl 0x631644': 0x00631644,
    'bl 0x631a04': 0x00631a04,
    'bl 0x631fc8': 0x00631fc8,
    'bl 0x632fc4': 0x00632fc4,
    'bl 0x633094': 0x00633094,
    'bl 0x6330e0': 0x006330e0,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl method.std::__1::list_unsigned_long_long__std::__1::allocator_unsigned_long_long___._list__': 0x00628094,
    'bl method.std::__1::list_unsigned_long_long__std::__1::allocator_unsigned_long_long___.pop_front__': 0x006293e8,
    'bl method.std::__1::list_unsigned_long_long__std::__1::allocator_unsigned_long_long___.push_back_unsigned_long_long_const_': 0x00629000,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.imp.sinf': 0x001c2b34,
    'bl sym.itemTypeIsBlock_ItemType_': 0x004cc11c,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsAirOrSnow_Tile_': 0x00a12760,
}

SPECS = [
    dict(
        name='fb_00',
        method='FreeBlock -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=6465264,
        end=6467828,
        disasm='disasm_worldtileloader_fb_00.txt',
        base_add=6465280,
        base_literal=6467824,
        boundary='ARM.exidx end 0x0062b0f4 (listing bound); next ObjC IMP 0x0062ba94 FreeBlock -[remoteUpdate:]',
        selectors={
                 0x62b09c: (15200004, 'count'),
                 0x62b0a0: (15199996, 'dynamicObjectNetData'),
                 0x62b0a4: (15200000, 'dataWithBytes:length:'),
                 0x62b0bc: (15199992, 'uniqueID'),
                 0x62b0c0: (15200008, 'dictionary'),
                 0x62b0cc: (15199972, 'setObject:forKey:'),
                 0x62b0d0: (15199848, 'countByEnumeratingWithState:objects:count:'),
                 0x62b0d4: (15199844, 'array'),
                 0x62b0dc: (15199852, 'itemType'),
                 0x62b0e0: (15199856, 'addObject:'),
                 0x62b0e4: (15199988, 'saveData'),
                 0x62b0ec: (15200012, 'appendData:'),
        },
        imports={
                 0x62b098: (17151904, 'objc_msgSend'),
                 0x62b0c8: (16247128, '__CFConstantStringClassReference'),
                 0x62b0e8: (16247112, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x62b070: (17157056, 'OBJC_IVAR_$_FreeBlock.dynamicObjectSaveDict', 140),
                 0x62b074: (17157072, 'OBJC_IVAR_$_FreeBlock.hovers', 64),
                 0x62b078: (17157048, 'OBJC_IVAR_$_FreeBlock.itemType', 56),
                 0x62b080: (17157080, 'OBJC_IVAR_$_FreeBlock.dataA', 60),
                 0x62b084: (17157076, 'OBJC_IVAR_$_FreeBlock.dataB', 62),
                 0x62b088: (17157092, 'OBJC_IVAR_$_FreeBlock.fallSpeed', 72),
                 0x62b08c: (17157104, 'OBJC_IVAR_$_FreeBlock.xVelocity', 116),
                 0x62b090: (17157088, 'OBJC_IVAR_$_FreeBlock.yVelocity', 124),
                 0x62b094: (17157084, 'OBJC_IVAR_$_FreeBlock.subItems', 112),
                 0x62b0ac: (17157108, 'OBJC_IVAR_$_FreeBlock.soundType', 148),
                 0x62b0b0: (17157112, 'OBJC_IVAR_$_FreeBlock.creationSoundPlayTime', 144),
                 0x62b0b4: (17157068, 'OBJC_IVAR_$_FreeBlock.priorityBlockhead', 136),
        },
        classes={
                 0x62b0a8: (15245752, 'OBJC_CLASS_$_NSMutableData'),
                 0x62b0c4: (15245756, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x62b0d8: (15245740, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6465264, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6467824, 'adceq r5, r3, ip, ror 7')],
        calls=[(6465692, 'blx r2'), (6465792, 'bl loc.imp.objc_msgSend_stret'), (6465828, 'bl sym.imp.memset'), (6466008, 'bl loc.imp.objc_msgSend'), (6466104, 'blx ip'), (6466204, 'blx r3'), (6466328, 'blx ip'), (6466432, 'blx r2'), (6466560, 'blx r2'), (6466584, 'bl sym.imp.memset'), (6466648, 'blx lr'), (6466748, 'bl sym.imp.objc_enumerationMutation'), (6466884, 'blx r2'), (6466908, 'bl sym.imp.memset'), (6466956, 'blx lr'), (6467056, 'bl sym.imp.objc_enumerationMutation'), (6467128, 'blx r2'), (6467208, 'blx ip'), (6467240, 'blx r3'), (6467344, 'blx ip'), (6467420, 'blx r3'), (6467520, 'blx ip'), (6467612, 'blx ip'), (6467620, 'bl 0x62b0f4'), (6467672, 'blx r3')],
        branches=[(6465580, 'bne', 6465720), (6465628, 'beq', 6465712), (6465776, 'beq', 6465800), (6465796, 'b', 6465832), (6466120, 'bne', 6466140), (6466132, 'b', 6467684), (6466240, 'beq', 6466332), (6466368, 'beq', 6467616), (6466440, 'bls', 6467616), (6466660, 'beq', 6467544), (6466740, 'beq', 6466752), (6466968, 'beq', 6467368), (6467048, 'beq', 6467060), (6467136, 'beq', 6467244), (6467244, 'b', 6467248), (6467272, 'blo', 6467012), (6467364, 'bne', 6467012), (6467368, 'b', 6467372), (6467448, 'blo', 6466704), (6467540, 'bne', 6466704), (6467544, 'b', 6467548)],
        semantics=('[FreeBlock -[creationNetDataForClient:]] (imp 0x0062a6f0, 641w): -[creationNetDataForClient:] (0x62a6f0, 641w): builds the 0x38-byte creation record at fp-0x68 {+0x00..0x17 [self dynamicObjectNetData] (stret 0x18; nil->memset) | +0x18 [priorityBlockhead@136 uniqueID] u64 | +0x20 u16 itemType@56 | +0x22 u16 dataA@60 | +0x24 u16 dataB@62 | +0x26 u16 (fallSpeed@72*255.0f) | +0x28 u16 (xVelocity@116*255) | +0x2a u16 (yVelocity@124*255) | +0x2c f32 creationSoundPlayTime@144 | +0x30 s8 soundType@148 | +0x31 u8 hovers@64 | +0x32 u8 hasExtra}; hasExtra = (saveDict!=nil) ? 1 : (subItems!=nil && [subItems count]>0); if hasExtra appends gzip(plist(dict)) built by local helper 0x62b0f4, dict = { "dynamicObjectSaveDict": self->dynamicObjectSaveDict@140 (CFSTR 0xf7e958) if non-nil, "subItems": items } where items = array of per-stack arrays of [elem saveData] over the double enumeration of subItems@112, skipping elements with [elem itemType] == 0xb (CFSTR 0xf7e948); returns [NSMutableData dataWithBytes:length:0x38]; the (data) argument is never read. 255.0f pool 0x62aa58..\n'),
    ),
    dict(
        name='fb_01',
        method='FreeBlock -[creationNetDataForFreeblockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:priorityBlockhead:soundType:creationSoundPlayTime:]',
        types='@52@0:4{?=ii}8i16S20S24@28@32c36@40i44f48',
        start=6468192,
        end=6470292,
        disasm='disasm_worldtileloader_fb_01.txt',
        base_add=6468208,
        base_literal=6470288,
        boundary='ARM.exidx end 0x0062ba94 (listing bound); next ObjC IMP 0x0062ba94 FreeBlock -[remoteUpdate:]',
        selectors={
                 0x62ba4c: (15200004, 'count'),
                 0x62ba50: (15200000, 'dataWithBytes:length:'),
                 0x62ba58: (15199992, 'uniqueID'),
                 0x62ba60: (15200008, 'dictionary'),
                 0x62ba6c: (15199972, 'setObject:forKey:'),
                 0x62ba70: (15199848, 'countByEnumeratingWithState:objects:count:'),
                 0x62ba74: (15199844, 'array'),
                 0x62ba7c: (15199852, 'itemType'),
                 0x62ba80: (15199856, 'addObject:'),
                 0x62ba84: (15199988, 'saveData'),
                 0x62ba8c: (15200012, 'appendData:'),
        },
        imports={
                 0x62ba48: (17151904, 'objc_msgSend'),
                 0x62ba68: (16247128, '__CFConstantStringClassReference'),
                 0x62ba88: (16247112, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0x62ba54: (15245752, 'OBJC_CLASS_$_NSMutableData'),
                 0x62ba64: (15245756, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x62ba78: (15245740, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6468192, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6470288, 'adceq r4, r3, ip, ror r8')],
        calls=[(6468516, 'blx r2'), (6468672, 'bl loc.imp.objc_msgSend'), (6468736, 'blx ip'), (6468832, 'blx r3'), (6468920, 'blx ip'), (6468980, 'blx r2'), (6469096, 'blx r2'), (6469120, 'bl sym.imp.memset'), (6469168, 'blx lr'), (6469268, 'bl sym.imp.objc_enumerationMutation'), (6469404, 'blx r2'), (6469428, 'bl sym.imp.memset'), (6469476, 'blx lr'), (6469576, 'bl sym.imp.objc_enumerationMutation'), (6469648, 'blx r2'), (6469728, 'blx ip'), (6469760, 'blx r3'), (6469864, 'blx ip'), (6469940, 'blx r3'), (6470040, 'blx ip'), (6470132, 'blx ip'), (6470140, 'bl 0x62b0f4'), (6470192, 'blx r3')],
        branches=[(6468448, 'bne', 6468544), (6468472, 'beq', 6468536), (6468752, 'bne', 6468772), (6468764, 'b', 6470204), (6468852, 'beq', 6468924), (6468936, 'beq', 6470136), (6468988, 'bls', 6470136), (6469180, 'beq', 6470064), (6469260, 'beq', 6469272), (6469488, 'beq', 6469888), (6469568, 'beq', 6469580), (6469656, 'beq', 6469764), (6469764, 'b', 6469768), (6469792, 'blo', 6469532), (6469884, 'bne', 6469532), (6469888, 'b', 6469892), (6469968, 'blo', 6469224), (6470060, 'bne', 6469224), (6470064, 'b', 6470068)],
        semantics=('[FreeBlock -[creationNetDataForFreeblockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:priorityBlockhead:soundType:creationSoundPlayTime:]] (imp 0x0062b260, 525w): +[FreeBlock creationNetDataForFreeblockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:priorityBlockhead:soundType:creationSoundPlayTime:] (class method, 0x62b260, 525w): class-side twin of fb_00; builds the same 0x38 record at fp-0x88 with defaults uniqueID = 0xffffffffffffffff (mvn 0 x2), fallSpeed/xVelocity/yVelocity = (u16)(0.0f*255) = 0, and from args: +0x08 pos.x, +0x0c pos.y, +0x18 [priorityBlockhead uniqueID] u64, +0x20 ofType, +0x22/+0x24 dataA/dataB, +0x2c creationSoundPlayTime f32, +0x30 soundType, +0x31 hovers, +0x32 hasExtra (same rule); bytes +0x11..+0x17 are never written (stale stack); same dict build + 0xb filter + helper 0x62b0f4 + appendData; returns d = [NSMutableData dataWithBytes:length:0x38]. 255.0f pool 0x62b4a0..\n'),
    ),
    dict(
        name='fb_02',
        method='FreeBlock -[creationSoundPlayTime]',
        types='f8@0:4',
        start=6506772,
        end=6506844,
        disasm='disasm_worldtileloader_fb_02.txt',
        base_add=6506796,
        base_literal=6506840,
        boundary='ARM.exidx end 0x006349a8; body trimmed at the next IMP 0x0063495c FreeBlock -[setCreationSoundPlayTime:]',
        selectors={},
        imports={},
        ivars={
                 0x634954: (17157112, 'OBJC_IVAR_$_FreeBlock.creationSoundPlayTime', 144),
        },
        classes={},
        instructions=[(6506772, 'sub sp, sp, 0xc'), (6506840, 'adceq fp, r2, r0, asr 3')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[creationSoundPlayTime]] (imp 0x00634914, 18w): -[creationSoundPlayTime] (0x634914, 18w): offset-cell getter of the float creationSoundPlayTime@144 (vldr s0 / vmov r0,s0 softfp return), dmb ish after the load; TRIMMED at IMP 0x63495c..\n'),
    ),
    dict(
        name='fb_03',
        method='FreeBlock -[dataA]',
        types='S8@0:4',
        start=6506176,
        end=6506236,
        disasm='disasm_worldtileloader_fb_03.txt',
        base_add=6506184,
        base_literal=6506232,
        boundary='ARM.exidx end 0x006346fc (listing bound); next ObjC IMP 0x006346fc FreeBlock -[setDataA:]',
        selectors={},
        imports={},
        ivars={
                 0x6346f4: (17157080, 'OBJC_IVAR_$_FreeBlock.dataA', 60),
        },
        classes={},
        instructions=[(6506176, 'sub sp, sp, 8'), (6506232, 'adceq fp, r2, r4, lsr 8')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[dataA]] (imp 0x006346c0, 15w): -[dataA] (0x6346c0, 15w): offset-cell getter of u16 dataA@60 (`ldrh r0,[self+60]`), no barrier..\n'),
    ),
    dict(
        name='fb_04',
        method='FreeBlock -[dataB]',
        types='S8@0:4',
        start=6506308,
        end=6506368,
        disasm='disasm_worldtileloader_fb_04.txt',
        base_add=6506316,
        base_literal=6506364,
        boundary='ARM.exidx end 0x00634780 (listing bound); next ObjC IMP 0x00634780 FreeBlock -[setDataB:]',
        selectors={},
        imports={},
        ivars={
                 0x634778: (17157076, 'OBJC_IVAR_$_FreeBlock.dataB', 62),
        },
        classes={},
        instructions=[(6506308, 'sub sp, sp, 8'), (6506364, 'adceq fp, r2, r0, lsr 7')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[dataB]] (imp 0x00634744, 15w): -[dataB] (0x634744, 15w): offset-cell getter of u16 dataB@62 (`ldrh r0,[self+62]`)..\n'),
    ),
    dict(
        name='fb_05',
        method='FreeBlock -[dealloc]',
        types='v8@0:4',
        start=6460672,
        end=6461040,
        disasm='disasm_worldtileloader_fb_05.txt',
        base_add=6460688,
        base_literal=6461036,
        boundary='ARM.exidx end 0x00629670 (listing bound); next ObjC IMP 0x00629670 FreeBlock -[removeFromMacroBlock]',
        selectors={
                 0x62964c: (15199956, 'dealloc'),
                 0x629658: (15199936, 'release'),
        },
        imports={
                 0x629648: (17151900, 'objc_msgSendSuper2'),
                 0x629654: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x62965c: (17157064, 'OBJC_IVAR_$_FreeBlock.blockCube', 88),
                 0x629660: (17157056, 'OBJC_IVAR_$_FreeBlock.dynamicObjectSaveDict', 140),
                 0x629664: (17157084, 'OBJC_IVAR_$_FreeBlock.subItems', 112),
                 0x629668: (17157068, 'OBJC_IVAR_$_FreeBlock.priorityBlockhead', 136),
        },
        classes={
                 0x629650: (15252600, 'OBJC_CLASS_$_FreeBlock'),
        },
        instructions=[(6460672, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6461036, 'invalid')],
        calls=[(6460840, 'blx r5'), (6460876, 'blx r3'), (6460912, 'blx r3'), (6460948, 'blx r3'), (6460988, 'blx r2')],
        branches=[],
        semantics=('[FreeBlock -[dealloc]] (imp 0x00629500, 92w): -[dealloc] (0x629500, 92w, 5 call rows): release-based teardown - [self->priorityBlockhead@136 release]; [self->subItems@112 release]; [self->dynamicObjectSaveDict@140 release]; [self->blockCube@88 release]; then objc_msgSendSuper2({self, FreeBlock class cell 0xe8bc78}, @selector(dealloc)). Scalar ivars (itemType/dataA/dataB/hovers/light*/heat/soundType/creationSoundPlayTime) need no release; no dmb..\n'),
    ),
    dict(
        name='fb_06',
        method='FreeBlock -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=6486120,
        end=6493276,
        disasm='disasm_worldtileloader_fb_06.txt',
        base_add=6486148,
        base_literal=6488996,
        boundary='ARM.exidx end 0x0063145c (listing bound); next ObjC IMP 0x006343f4 FreeBlock -[falling]',
        selectors={
                 0x630b94: (15199912, 'objectType'),
                 0x630b98: (15199916, 'dynamicWorldChangedAtPos:objectType:'),
                 0x630ba4: (15200060, 'worldWidthMacro'),
                 0x631150: (15200044, 'macroTiles'),
                 0x631438: (15200084, 'dayColor'),
        },
        imports={
                 0x63114c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6303a8: (17157096, 'OBJC_IVAR_$_FreeBlock.bounceTimer', 68),
                 0x6303ac: (17157060, 'OBJC_IVAR_$_FreeBlock.rotation', 76),
                 0x630b88: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x630b90: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x630ba0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x630bc4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x631148: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x631430: (17157060, 'OBJC_IVAR_$_FreeBlock.rotation', 76),
                 0x631434: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x63143c: (17157064, 'OBJC_IVAR_$_FreeBlock.blockCube', 88),
                 0x631440: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x631448: (17157048, 'OBJC_IVAR_$_FreeBlock.itemType', 56),
                 0x63144c: (17157080, 'OBJC_IVAR_$_FreeBlock.dataA', 60),
                 0x631450: (17157076, 'OBJC_IVAR_$_FreeBlock.dataB', 62),
                 0x631454: (17157052, 'OBJC_IVAR_$_FreeBlock.paintColor', 152),
        },
        classes={},
        instructions=[(6486120, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6493272, 'adceq lr, r2, r8, asr 25')],
        calls=[(6486948, 'bl sym.imp.sinf'), (6487156, 'bl loc.imp.objc_msgSend'), (6487192, 'bl loc.imp.objc_msgSend'), (6487292, 'bl loc.imp.objc_msgSend'), (6487316, 'bl sym.imp.__aeabi_idiv'), (6487384, 'bl loc.imp.objc_msgSend'), (6487508, 'bl loc.imp.objc_msgSend'), (6487524, 'bl sym.imp.__aeabi_idiv'), (6487592, 'bl loc.imp.objc_msgSend'), (6487716, 'bl loc.imp.objc_msgSend'), (6487740, 'bl sym.imp.__aeabi_idiv'), (6487808, 'bl loc.imp.objc_msgSend'), (6487936, 'bl loc.imp.objc_msgSend'), (6487952, 'bl sym.imp.__aeabi_idiv'), (6488020, 'bl loc.imp.objc_msgSend'), (6488288, 'bl method.Vector2.operator_float__'), (6488348, 'bl loc.imp.objc_msgSend'), (6488372, 'bl sym.imp.__aeabi_idiv'), (6488464, 'bl loc.imp.objc_msgSend'), (6488496, 'bl method.Vector2.operator_float__'), (6488548, 'bl method.Vector2.operator_float__'), (6488612, 'bl loc.imp.objc_msgSend'), (6488628, 'bl sym.imp.__aeabi_idiv'), (6488720, 'bl loc.imp.objc_msgSend'), (6488752, 'bl method.Vector2.operator_float__'), (6488924, 'blx r2'), (6488968, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (6489060, 'bl sym.imp.sinf'), (6489236, 'bl method.Vector2.operator_float__'), (6489252, 'bl method.Vector2.operator_float__'), (6489480, 'bl 0x63145c'), (6489856, 'bl 0x631644'), (6490684, 'bl 0x631a04'), (6490760, 'bl loc.imp.objc_msgSend_stret'), (6490796, 'bl sym.imp.memset'), (6491316, 'bl method.Vector.Vector_float__float__float_'), (6491332, 'bl method.Vector.operator_float__'), (6491388, 'bl method.Vector.operator_float__'), (6491424, 'bl method.Vector.operator_float__'), (6491480, 'bl method.Vector.operator_float__'), (6491516, 'bl method.Vector.operator_float__'), (6491572, 'bl method.Vector.operator_float__'), (6491624, 'bl method.Vector.Vector_float__float__float_'), (6491864, 'bl 0x632fc4'), (6492468, 'bl 0x631fc8'), (6492548, 'bl 0x633094'), (6493220, 'bl 0x6330e0')],
        branches=[(6486848, 'bpl', 6487012), (6487008, 'b', 6487200), (6487072, 'bhi', 6487196), (6487196, 'b', 6487200), (6487328, 'blt', 6487420), (6487412, 'b', 6487624), (6487536, 'bge', 6487620), (6487620, 'b', 6487624), (6487752, 'blt', 6487848), (6487836, 'b', 6488052), (6487964, 'bge', 6488048), (6488048, 'b', 6488052), (6488088, 'blt', 6488212), (6488128, 'bgt', 6488212), (6488168, 'blt', 6488212), (6488208, 'ble', 6488216), (6488212, 'b', 6493224), (6488396, 'ble', 6488520), (6488516, 'b', 6488776), (6488652, 'bpl', 6488772), (6488772, 'b', 6488776), (6488808, 'beq', 6488816), (6488812, 'b', 6493224), (6488988, 'bne', 6489012), (6488992, 'b', 6493224), (6490744, 'beq', 6490768), (6490764, 'b', 6490800), (6490920, 'bpl', 6490940), (6490936, 'b', 6490952), (6490996, 'bpl', 6491096), (6491012, 'b', 6491108), (6491152, 'ble', 6491224), (6491668, 'beq', 6492504), (6492472, 'b', 6493224)],
        semantics=('[FreeBlock -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x0062f868, 1789w): [census] -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] (0x62f868, 1789w, 34 branches, 47 call rows; void; frame 156: dt float + 2x GLKMatrix4 + 4 camera ints). Phase 1 (0x62f9a4-0x62fc9c): clocks - bounceTimer@68 += dt, rotation@76 += dt; if bounceTimer < 1.0: bounceY = |sinf(rotation*2*pi)*(1-bounceTimer)*5.0| (pi double 0x400921fb54442d18 @0x62ff20) -> local render struct +0x21c; else on the crossing frame (bounceTimer-dt <= 1.0): [self->dynamicWorld dynamicWorldChangedAtPos:self.pos objectType:[self objectType]] (sels 0x630b94/0x630b98). Phase 2 (0x62fca0-0x630094) camera-cull: 4 blocks of [self->world@4 worldWidthMacro] (objc) + __aeabi_idiv (x6) folding pos.x/pos.y into the camera window via worldWidthMacro*32, then a 4-way float compare chain bails to the epilogue 0x631428 when off-camera. Phase 3 (0x630098-0x6303b0): screen position = floatPos.x - (float)cameraMinXWorld (+ y, same), wrap by worldWidthMacro*32; tile = tileAtWorldPosition(self.pos.x, self.pos.y, [self->world macroTiles], self->world); tile==0 -> return. Phase 4 (0x6303b4-0x63058c): wobble sinf(rotation*4.0f)*0.1f (pool 0x6303b0) added to bounceY; writes the animated position vector; bl helper 0x63145c. Phase 5 (0x630588-0x630e14): bl 0x631644; bl 0x631a04; [self->world dayColor] via objc_msgSend_stret (0x10-byte struct, memset-0 when world nil, sel 0x630a44... cell 0xf7..); tile light = u16 tile[0xe]/[0x10]/[0x12] / 1024.0f (pool 0x630bcc) -> struct +0x28/+0x24/+0x20, copied to +0x14/+0x18/+0x1c; long float compositing (255.0f @0x630bd4, 0.3f @0x630bd0, div/mul chains, Vector::Vector(f,f,f) x2) into the struct color area. Phase 6a (0x630e14-0x631158): if self->blockCube@88 != 0: copy matrices + dir from cache@32/rotation@76, bl 0x632fc4 (cube render), write the big param struct +4..+0x166, bl 0x631fc8. Phase 6b (0x631158-0x631428): else Vector(-0.5f,-0.3f,1.0f) + bl 0x633094 and itemType@56/dataA@60/dataB@62/paintColor@152 via cache@32 + bl 0x6330e0 (item-icon quad fallback). Local helpers beyond the batch: 0x63145c, 0x631644, 0x631a04, 0x631fc8, 0x632fc4, 0x633094, 0x6330e0..\n'),
    ),
    dict(
        name='fb_07',
        method='FreeBlock -[dynamicObjectSaveDict]',
        types='@8@0:4',
        start=6506576,
        end=6506644,
        disasm='disasm_worldtileloader_fb_07.txt',
        base_add=6506600,
        base_literal=6506640,
        boundary='ARM.exidx end 0x00634894 (listing bound); next ObjC IMP 0x00634894 FreeBlock -[hovers]',
        selectors={},
        imports={},
        ivars={
                 0x63488c: (17157056, 'OBJC_IVAR_$_FreeBlock.dynamicObjectSaveDict', 140),
        },
        classes={},
        instructions=[(6506576, 'sub sp, sp, 0xc'), (6506640, 'adceq fp, r2, r4, lsl 5')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[dynamicObjectSaveDict]] (imp 0x00634850, 17w): -[dynamicObjectSaveDict] (0x634850, 17w): offset-cell getter of dynamicObjectSaveDict@140 with dmb ish..\n'),
    ),
    dict(
        name='fb_08',
        method='FreeBlock -[falling]',
        types='c8@0:4',
        start=6505460,
        end=6505756,
        disasm='disasm_worldtileloader_fb_08.txt',
        base_add=6505476,
        base_literal=6505752,
        boundary='ARM.exidx end 0x0063451c (listing bound); next ObjC IMP 0x0063451c FreeBlock -[priorityBlockheadCannotPickup]',
        selectors={
                 0x634510: (15200044, 'macroTiles'),
        },
        imports={
                 0x63450c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x634504: (17157072, 'OBJC_IVAR_$_FreeBlock.hovers', 64),
                 0x634508: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x634514: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(6505460, 'push {r4, sl, fp, lr}'), (6505752, 'adceq fp, r2, r8, ror 13')],
        calls=[(6505636, 'blx r2'), (6505680, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (6505692, 'bl sym.tileIsAirOrSnow_Tile_')],
        branches=[(6505520, 'bne', 6505712), (6505708, 'b', 6505720)],
        semantics=('[FreeBlock -[falling]] (imp 0x006343f4, 74w): -[falling] (0x6343f4, 74w): returns NO when self->hovers@64 != 0; otherwise [self->world@4 macroTiles] then tileAtWorldPosition(pos.x@16, pos.y-1, macroTiles, world) and returns tileIsAirOrSnow(tile) - i.e. only a non-hovering block over an air/snow tile is still falling..\n'),
    ),
    dict(
        name='fb_09',
        method='FreeBlock -[hitLava]',
        types='v8@0:4',
        start=6470872,
        end=6471656,
        disasm='disasm_worldtileloader_fb_09.txt',
        base_add=6470904,
        base_literal=6471612,
        boundary='ARM.exidx end 0x0062bfe8 (listing bound); next ObjC IMP 0x0062bfe8 FreeBlock -[update:accurateDT:isSimulation:]',
        selectors={
                 0x62bfb8: (15200020, 'setNeedsRemoved:'),
                 0x62bfc8: (15200024, 'instance'),
                 0x62bfd0: (15200028, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
                 0x62bfd8: (15200032, 'multiSoundNamed:'),
                 0x62bfe0: (15200036, 'playAtPosition:'),
        },
        imports={
                 0x62bfdc: (16247176, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x62bfc0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x62bfc4: (15245760, 'OBJC_CLASS_$_ParticleEmitter'),
                 0x62bfd4: (15245764, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(6470872, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6471652, 'andeq r0, r0, r0')],
        calls=[(6470924, 'bl loc.imp.objc_msgSend'), (6470956, 'bl method.Vector2.operator_float__'), (6470988, 'bl method.Vector2.operator_float__'), (6471032, 'bl method.Vector.Vector_float__float__float_'), (6471076, 'bl method.Vector.Vector_float__float__float__float_'), (6471104, 'bl loc.imp.objc_msgSend'), (6471112, 'bl 0x625fd8'), (6471164, 'bl method.Vector.Vector_float__float__float_'), (6471204, 'bl method.Vector.operator_Vector_'), (6471208, 'bl 0x625fd8'), (6471240, 'bl 0x625fd8'), (6471292, 'bl method.Vector.Vector_float__float__float_'), (6471496, 'bl loc.imp.objc_msgSend'), (6471520, 'bl loc.imp.objc_msgSend'), (6471544, 'bl loc.imp.objc_msgSend'), (6471596, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[FreeBlock -[hitLava]] (imp 0x0062bcd8, 196w): -[hitLava] (0x62bcd8, 196w, 16 call rows): [self setNeedsRemoved:1]; then lava-death FX: [ParticleEmitter instance] + [emitter addParticleAtPos:pos velocity:vel color:(0.4f,0.2f,0.2f,0.5f) gravityType:0 life:1.0f scale:12.0f], where pos = Vector4((floatPos.x@24, floatPos.y-5.0f, -0.3f(0xbe99999a)) + (0,0,u1-5)) and vel = (u2-5, u3*5+5, 0); uN = lrand48()/2^31 (helper 0x625fd8 trampolines lrand48 via PLT 0x1c2804 -> GOT 0x105fb10; divisor 0x4f000000 = 2^31 @0x62bfcc); then [MJSoundManager instance] multiSoundNamed:@"freeblockLavaHiss.wav" (CFSTR 0xf7e988) + playAtPosition:(floatPos.x, floatPos.y)..\n'),
    ),
    dict(
        name='fb_10',
        method='FreeBlock -[hovers]',
        types='c8@0:4',
        start=6506644,
        end=6506704,
        disasm='disasm_worldtileloader_fb_10.txt',
        base_add=6506652,
        base_literal=6506700,
        boundary='ARM.exidx end 0x006348d0 (listing bound); next ObjC IMP 0x006348d0 FreeBlock -[setHovers:]',
        selectors={},
        imports={},
        ivars={
                 0x6348c8: (17157072, 'OBJC_IVAR_$_FreeBlock.hovers', 64),
        },
        classes={},
        instructions=[(6506644, 'sub sp, sp, 8'), (6506700, 'adceq fp, r2, r0, asr r2')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[hovers]] (imp 0x00634894, 15w): -[hovers] (0x634894, 15w): offset-cell getter of BOOL hovers@64 (ldrsb)..\n'),
    ),
    dict(
        name='fb_11',
        method='FreeBlock -[initSubDerivedObjects]',
        types='v8@0:4',
        start=6446224,
        end=6447064,
        disasm='disasm_worldtileloader_fb_11.txt',
        base_add=6446240,
        base_literal=6447060,
        boundary='ARM.exidx end 0x00625fd8 (listing bound); next ObjC IMP 0x00625fe8 FreeBlock -[objectType]',
        selectors={
                 0x625f9c: (15199820, 'unsignedIntValue'),
                 0x625fa4: (15199816, 'objectForKey:'),
                 0x625fbc: (15199832, 'initItemBlockOfType:level:paint:size:world:'),
                 0x625fc4: (15199828, 'intValue'),
                 0x625fcc: (15199824, 'alloc'),
        },
        imports={
                 0x625f98: (17151904, 'objc_msgSend'),
                 0x625fa0: (16246936, '__CFConstantStringClassReference'),
                 0x625fc8: (16246952, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x625f90: (17157048, 'OBJC_IVAR_$_FreeBlock.itemType', 56),
                 0x625f94: (17157052, 'OBJC_IVAR_$_FreeBlock.paintColor', 152),
                 0x625fa8: (17157056, 'OBJC_IVAR_$_FreeBlock.dynamicObjectSaveDict', 140),
                 0x625fac: (17157060, 'OBJC_IVAR_$_FreeBlock.rotation', 76),
                 0x625fb4: (17157064, 'OBJC_IVAR_$_FreeBlock.blockCube', 88),
                 0x625fc0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0x625fd0: (15245736, 'OBJC_CLASS_$_DrawCube'),
        },
        instructions=[(6446224, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6447060, 'adceq sb, r3, ip, asr 28')],
        calls=[(6446256, 'bl 0x625fd8'), (6446440, 'blx ip'), (6446456, 'blx r2'), (6446500, 'bl sym.itemTypeIsBlock_ItemType_'), (6446716, 'blx r2'), (6446796, 'blx r4'), (6446812, 'blx r2'), (6446952, 'blx r7')],
        branches=[(6446512, 'beq', 6446976)],
        semantics=('[FreeBlock -[initSubDerivedObjects]] (imp 0x00625c90, 210w): -[initSubDerivedObjects] (0x625c90, 210w): (1) rotation@76 = (float)(2*pi * lrand48()/2^31) - random full turn (pi double @0x625f88, 2.0 dbl, divisor 2^31 @0x625fb0); (2) paintColor@152 = [[self->dynamicObjectSaveDict@140 objectForKey:@"paintColor"] (CFSTR 0xf7e898) unsignedIntValue] (nil-safe); (3) if itemTypeIsBlock(self->itemType@56): self->blockCube@88 = [[DrawCube alloc] initItemBlockOfType:self->itemType level:[[saveDict objectForKey:@"level"] (CFSTR 0xf7e8a8) intValue] paint:(self->paintColor != 0) size:0.4f (0x3ecccccd @0x625fb8) world:self->world@4]..\n'),
    ),
    dict(
        name='fb_12',
        method='FreeBlock -[initWithWorld:dynamicWorld:atPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:cache:hovers:priorityBlockhead:]',
        types='@56@0:4@8@12{?=ii}16i24S28S32@36@40@44c48@52',
        start=6447108,
        end=6449472,
        disasm='disasm_worldtileloader_fb_12.txt',
        base_add=6447124,
        base_literal=6449468,
        boundary='ARM.exidx end 0x00626940 (listing bound); next ObjC IMP 0x00626940 FreeBlock -[updatePosition:]',
        selectors={
                 0x6268d0: (15199836, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0x6268dc: (15199840, 'retain'),
                 0x6268f4: (15199848, 'countByEnumeratingWithState:objects:count:'),
                 0x6268f8: (15199844, 'array'),
                 0x626900: (15199852, 'itemType'),
                 0x626904: (15199856, 'addObject:'),
                 0x626928: (15199864, 'initSubDerivedObjects'),
                 0x626930: (15199860, 'worldTime'),
        },
        imports={
                 0x6268d8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6268d4: (17157056, 'OBJC_IVAR_$_FreeBlock.dynamicObjectSaveDict', 140),
                 0x6268e0: (17157068, 'OBJC_IVAR_$_FreeBlock.priorityBlockhead', 136),
                 0x6268e4: (17157072, 'OBJC_IVAR_$_FreeBlock.hovers', 64),
                 0x6268e8: (17157076, 'OBJC_IVAR_$_FreeBlock.dataB', 62),
                 0x6268ec: (17157080, 'OBJC_IVAR_$_FreeBlock.dataA', 60),
                 0x6268f0: (17157048, 'OBJC_IVAR_$_FreeBlock.itemType', 56),
                 0x626908: (17157084, 'OBJC_IVAR_$_FreeBlock.subItems', 112),
                 0x62690c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x626914: (17157088, 'OBJC_IVAR_$_FreeBlock.yVelocity', 124),
                 0x62691c: (17157092, 'OBJC_IVAR_$_FreeBlock.fallSpeed', 72),
                 0x626920: (17157096, 'OBJC_IVAR_$_FreeBlock.bounceTimer', 68),
                 0x62692c: (17157100, 'OBJC_IVAR_$_FreeBlock.creationTime', 80),
                 0x626934: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x626938: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0x6268c8: (15252600, 'OBJC_CLASS_$_FreeBlock'),
                 0x6268fc: (15245740, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6447108, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6449468, 'invalid')],
        calls=[(6447372, 'bl loc.imp.objc_msgSendSuper2'), (6447604, 'blx r3'), (6447644, 'blx r3'), (6447792, 'blx r2'), (6447816, 'bl sym.imp.memset'), (6447864, 'blx lr'), (6447964, 'bl sym.imp.objc_enumerationMutation'), (6448100, 'blx r2'), (6448124, 'bl sym.imp.memset'), (6448172, 'blx lr'), (6448272, 'bl sym.imp.objc_enumerationMutation'), (6448344, 'blx r2'), (6448412, 'blx r3'), (6448516, 'blx ip'), (6448592, 'blx r3'), (6448692, 'blx ip'), (6448776, 'blx r2'), (6448840, 'bl 0x625fd8'), (6448904, 'bl method.Vector2.operator_float__'), (6449136, 'bl method.Vector2.operator_float__'), (6449260, 'blx r5'), (6449328, 'blx ip')],
        branches=[(6447400, 'bne', 6447416), (6447412, 'b', 6449340), (6447680, 'beq', 6448804), (6447876, 'beq', 6448716), (6447956, 'beq', 6447968), (6448184, 'beq', 6448540), (6448264, 'beq', 6448276), (6448352, 'beq', 6448416), (6448416, 'b', 6448420), (6448444, 'blo', 6448228), (6448536, 'bne', 6448228), (6448540, 'b', 6448544), (6448620, 'blo', 6447920), (6448712, 'bne', 6447920), (6448716, 'b', 6448720), (6448728, 'beq', 6448800), (6448800, 'b', 6448804), (6448836, 'bne', 6448924), (6449024, 'ble', 6449068)],
        semantics=('[FreeBlock -[initWithWorld:dynamicWorld:atPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:cache:hovers:priorityBlockhead:]] (imp 0x00626004, 591w): [census-lite] -[initWithWorld:dynamicWorld:atPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:cache:hovers:priorityBlockhead:] (0x626004, 591w, 19 branches, 22 call rows): the explicit-args designated init. objc_msgSendSuper2 initWithWorld:dynamicWorld:atPosition:cache: (sel 0xe7ee5c, class marker FreeBlock); !self -> nil; copies itemType@56=ofType, dataA@60 (u16), dataB@62 (u16), hovers@64 (s8); retains priorityBlockhead@136 and dynamicObjectSaveDict@140; if subItems != nil: items = [NSMutableArray array]; double fast-enum of stacks/elements; keep elements with [elem itemType] != 0xb; only store subItems@112 = [items retain] when >= 1 kept; if hovers == 0: floatPos.x += lrand48()/2^31*5.0-2.0; bounceTimer@68 = 1.0f; fallSpeed@72 = -0.05f (0xbd4ccccd @0x626918); floatPos.y = (float)pos.y + 5.0f; creationTime@80 = [self->world worldTime] (double); yVelocity@124 = 5.0f; [self initSubDerivedObjects]; return self..\n'),
    ),
    dict(
        name='fb_13',
        method='FreeBlock -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=6455156,
        end=6455444,
        disasm='disasm_worldtileloader_fb_13.txt',
        base_add=6455316,
        base_literal=6455440,
        boundary='ARM.exidx end 0x00628094 (listing bound); next ObjC IMP 0x006280cc FreeBlock -[initWithWorld:dynamicWorld:cache:netData:avoidFreeblockDupeObjectIds:]',
        selectors={
                 0x62808c: (15199920, 'initWithWorld:dynamicWorld:cache:netData:avoidFreeblockDupeObjectIds:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(6455156, 'push {r4, r5, fp, lr}'), (6455440, 'invalid')],
        calls=[(6455348, 'bl loc.imp.objc_msgSend'), (6455380, 'bl method.std::__1::list_unsigned_long_long__std::__1::allocator_unsigned_long_long___._list__'), (6455420, 'bl method.std::__1::list_unsigned_long_long__std::__1::allocator_unsigned_long_long___._list__'), (6455432, 'bl sym.imp._Unwind_Resume')],
        branches=[(6455356, 'b', 6455360)],
        semantics=('[FreeBlock -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x00627f74, 72w): -[initWithWorld:dynamicWorld:cache:netData:] (0x627f74, 72w): convenience thunk - builds an empty std::__1::list<unsigned long long> on the stack (list<ull>::~list at 0x628054 / EH path 0x62807c + _Unwind_Resume) and tail-forwards to initWithWorld:dynamicWorld:cache:netData:avoidFreeblockDupeObjectIds: (sel 0xe7eeb0) with that list as the 6th argument (stack +8, type ^^{list<ull>}); returns the designated init\'s result..\n'),
    ),
    dict(
        name='fb_14',
        method='FreeBlock -[initWithWorld:dynamicWorld:cache:netData:avoidFreeblockDupeObjectIds:]',
        types='@28@0:4@8@12@16@20^{list<unsigned long long, std::__1::allocator<unsigned long long> >={__list_node_base<unsigned long long, void *>=^{__list_node<unsigned long long, void *>}^{__list_node<unsigned long long, void *>}}{__compressed_pair<unsigned long, std::__1::allocator<std::__1::__list_node<unsigned long long, void *> > >=L}}24',
        start=6455500,
        end=6459356,
        disasm='disasm_worldtileloader_fb_14.txt',
        base_add=6455520,
        base_literal=6459352,
        boundary='ARM.exidx end 0x00628fdc (listing bound); next ObjC IMP 0x00629500 FreeBlock -[dealloc]',
        selectors={
                 0x628f18: (15199924, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x628f28: (15199928, 'getBytes:length:'),
                 0x628f5c: (15199816, 'objectForKey:'),
                 0x628f60: (15199940, 'length'),
                 0x628f68: (15199944, 'subdataWithRange:'),
                 0x628f6c: (15199848, 'countByEnumeratingWithState:objects:count:'),
                 0x628f74: (15199892, 'init'),
                 0x628f78: (15199824, 'alloc'),
                 0x628f80: (15199856, 'addObject:'),
                 0x628f84: (15199844, 'array'),
                 0x628f88: (15199852, 'itemType'),
                 0x628f8c: (15199900, 'autorelease'),
                 0x628f90: (15199896, 'initWithSaveData:'),
                 0x628f9c: (15199904, 'copy'),
                 0x628fac: (15199948, 'unsignedLongValue'),
                 0x628fb0: (15199936, 'release'),
                 0x628fb4: (15199932, 'removeFromMacroBlock'),
                 0x628fb8: (15199952, 'isClient'),
                 0x628fc8: (15199840, 'retain'),
                 0x628fcc: (15199908, 'blockheadWithIDIncludingNet:'),
                 0x628fd4: (15199864, 'initSubDerivedObjects'),
        },
        imports={
                 0x628f14: (17151900, 'objc_msgSendSuper2'),
                 0x628f24: (17151904, 'objc_msgSend'),
                 0x628f58: (16247112, '__CFConstantStringClassReference'),
                 0x628fa0: (16247128, '__CFConstantStringClassReference'),
                 0x628fa8: (16247160, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x628f20: (17157048, 'OBJC_IVAR_$_FreeBlock.itemType', 56),
                 0x628f2c: (17157072, 'OBJC_IVAR_$_FreeBlock.hovers', 64),
                 0x628f30: (17157088, 'OBJC_IVAR_$_FreeBlock.yVelocity', 124),
                 0x628f34: (17157104, 'OBJC_IVAR_$_FreeBlock.xVelocity', 116),
                 0x628f38: (17157100, 'OBJC_IVAR_$_FreeBlock.creationTime', 80),
                 0x628f3c: (17157108, 'OBJC_IVAR_$_FreeBlock.soundType', 148),
                 0x628f40: (17157112, 'OBJC_IVAR_$_FreeBlock.creationSoundPlayTime', 144),
                 0x628f44: (17157076, 'OBJC_IVAR_$_FreeBlock.dataB', 62),
                 0x628f48: (17157080, 'OBJC_IVAR_$_FreeBlock.dataA', 60),
                 0x628f4c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x628f50: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x628f54: (17157096, 'OBJC_IVAR_$_FreeBlock.bounceTimer', 68),
                 0x628f70: (17157084, 'OBJC_IVAR_$_FreeBlock.subItems', 112),
                 0x628f98: (17157056, 'OBJC_IVAR_$_FreeBlock.dynamicObjectSaveDict', 140),
                 0x628fbc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x628fc0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x628fc4: (17157068, 'OBJC_IVAR_$_FreeBlock.priorityBlockhead', 136),
        },
        classes={
                 0x628f1c: (15252600, 'OBJC_CLASS_$_FreeBlock'),
                 0x628f7c: (15245740, 'OBJC_CLASS_$_NSMutableArray'),
                 0x628f94: (15245744, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(6455500, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6459352, 'adceq r7, r3, ip, lsl 20')],
        calls=[(6455664, 'blx r8'), (6455772, 'blx ip'), (6455892, 'blx ip'), (6455912, 'blx r2'), (6456240, 'bl 0x625fd8'), (6456304, 'bl method.Vector2.operator_float__'), (6456428, 'bl method.Vector2.operator_float__'), (6456480, 'bl loc.imp.objc_msgSend'), (6456548, 'bl loc.imp.objc_msgSend'), (6456560, 'bl 0x628fdc'), (6456616, 'blx ip'), (6456776, 'blx r2'), (6456792, 'blx r2'), (6456832, 'bl sym.imp.memset'), (6456880, 'blx lr'), (6456980, 'bl sym.imp.objc_enumerationMutation'), (6457156, 'blx r2'), (6457200, 'blx ip'), (6457220, 'bl sym.imp.memset'), (6457268, 'blx lr'), (6457368, 'bl sym.imp.objc_enumerationMutation'), (6457496, 'blx ip'), (6457516, 'blx r3'), (6457532, 'blx r2'), (6457556, 'blx r2'), (6457616, 'blx r3'), (6457720, 'blx ip'), (6457848, 'blx ip'), (6457968, 'blx r3'), (6457984, 'blx r2'), (6458112, 'bl loc.imp.objc_msgSend'), (6458128, 'bl loc.imp.objc_msgSend'), (6458640, 'bl method.std::__1::list_unsigned_long_long__std::__1::allocator_unsigned_long_long___.push_back_unsigned_long_long_const_'), (6458700, 'bl method.std::__1::list_unsigned_long_long__std::__1::allocator_unsigned_long_long___.pop_front__'), (6458776, 'blx ip'), (6458796, 'blx r2'), (6458880, 'blx r2'), (6459052, 'bl loc.imp.objc_msgSend'), (6459068, 'blx r2'), (6459132, 'blx r2')],
        branches=[(6455692, 'bne', 6455708), (6455704, 'b', 6459144), (6455824, 'bne', 6455936), (6455924, 'b', 6459144), (6456236, 'bne', 6456324), (6456448, 'beq', 6458820), (6456636, 'beq', 6457880), (6456892, 'beq', 6457872), (6456972, 'beq', 6456984), (6457280, 'beq', 6457744), (6457360, 'beq', 6457372), (6457564, 'beq', 6457620), (6457620, 'b', 6457624), (6457648, 'blo', 6457324), (6457740, 'bne', 6457324), (6457744, 'b', 6457748), (6457748, 'b', 6457752), (6457776, 'blo', 6456936), (6457868, 'bne', 6456936), (6457872, 'b', 6457876), (6457876, 'b', 6457880), (6458032, 'beq', 6458816), (6458052, 'beq', 6458816), (6458056, 'b', 6458060), (6458192, 'beq', 6458608), (6458212, 'beq', 6458608), (6458216, 'b', 6458220), (6458400, 'beq', 6458492), (6458452, 'bne', 6458464), (6458456, 'b', 6458460), (6458460, 'b', 6458492), (6458488, 'b', 6458332), (6458604, 'bne', 6458712), (6458624, 'beq', 6458708), (6458628, 'b', 6458632), (6458692, 'bls', 6458704), (6458704, 'b', 6458708), (6458708, 'b', 6458812), (6458808, 'b', 6459144), (6458812, 'b', 6458816), (6458816, 'b', 6458820), (6458892, 'bne', 6458928), (6458944, 'beq', 6459092), (6458948, 'b', 6458952)],
        semantics=('[FreeBlock -[initWithWorld:dynamicWorld:cache:netData:avoidFreeblockDupeObjectIds:]] (imp 0x006280cc, 964w): [census-lite] -[initWithWorld:dynamicWorld:cache:netData:avoidFreeblockDupeObjectIds:] (0x6280cc, 964w, 44 branches, 40 call rows): the net deserializer (inverse of fb_00). (1) objc_msgSendSuper2 initWithWorld:dynamicWorld:cache:netData: (sel 0xe7eeb4); !self -> nil. (2) [netData getBytes:buf length:0x38] (sel 0xe7eeb8); itemType@56 = (u16)record[0x20]; itemType == 0xb -> [self release]; return nil. (3) dataA@60 = (u16)record[0x22], dataB@62 = (u16)record[0x24], hovers@64 = (s8)record[0x31], creationSoundPlayTime@144 = f32 record[0x2c], soundType@148 = (s8)record[0x30], creationTime@80 = (double)f32 record[0x2c] (observed aliasing), xVelocity@116 = (s16)record[0x28]/255.0f, yVelocity@124 = (s16)record[0x2a]/255.0f; fallSpeed@72 NOT restored. (4) if hovers == 0: floatPos.x += lrand48()/2^31*5-2; bounceTimer@68 = 1.0f; floatPos.y = (float)pos.y+5.0f. (5) if record[0x32] (hasExtra): blob = [netData subdataWithRange:{0x38, len-0x38}], dict = local helper 0x628fdc (inflate+plist); if dict["subItems"] (CFSTR 0xf7e948) != nil: subItems@112 = [[NSMutableArray alloc] init] + per stack an [NSMutableArray array] holding [[[InventoryItem alloc] initWithSaveData:savedItem] autorelease] for [item itemType] != 0xb; dynamicObjectSaveDict@140 = [dict["dynamicObjectSaveDict"] (CFSTR 0xf7e958) copy]; if saveDict != nil && record+0x18 u64 != 0: uid = [[saveDict objectForKey:@"uniqueID"] (CFSTR 0xf7e978) unsignedLongValue]; if uid is in the avoidFreeblockDupeObjectIds std::list<ull> (inlined std::find) -> [self release]; return nil; else push_back(uid) and pop_front() when size > 0x20 (32-entry LRU). (6) if ![[self->dynamicWorld@8] isClient]: isNet@52 = 0. (7) if record+0x18 u64 != 0: priorityBlockhead@136 = [[dynamicWorld blockheadWithIDIncludingNet:uid] (sel 0xe7eea4) retain]. (8) [self initSubDerivedObjects]; return self..\n'),
    ),
    dict(
        name='fb_15',
        method='FreeBlock -[itemType]',
        types='i8@0:4',
        start=6506048,
        end=6506108,
        disasm='disasm_worldtileloader_fb_15.txt',
        base_add=6506072,
        base_literal=6506104,
        boundary='ARM.exidx end 0x0063467c (listing bound); next ObjC IMP 0x0063467c FreeBlock -[setItemType:]',
        selectors={},
        imports={},
        ivars={
                 0x634674: (17157048, 'OBJC_IVAR_$_FreeBlock.itemType', 56),
        },
        classes={},
        instructions=[(6506048, 'sub sp, sp, 8'), (6506104, 'umlaleq fp, r2, r4, r4')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[itemType]] (imp 0x00634640, 15w): -[itemType] (0x634640, 15w): offset-cell getter of int itemType@56 with dmb ish..\n'),
    ),
    dict(
        name='fb_16',
        method='FreeBlock -[priorityBlockhead]',
        types='@8@0:4',
        start=6506508,
        end=6506576,
        disasm='disasm_worldtileloader_fb_16.txt',
        base_add=6506532,
        base_literal=6506572,
        boundary='ARM.exidx end 0x00634894; body trimmed at the next IMP 0x00634850 FreeBlock -[dynamicObjectSaveDict]',
        selectors={},
        imports={},
        ivars={
                 0x634848: (17157068, 'OBJC_IVAR_$_FreeBlock.priorityBlockhead', 136),
        },
        classes={},
        instructions=[(6506508, 'sub sp, sp, 0xc'), (6506572, 'adceq fp, r2, r8, asr 5')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[priorityBlockhead]] (imp 0x0063480c, 17w): -[priorityBlockhead] (0x63480c, 17w): offset-cell getter of the object ivar priorityBlockhead@136 (dmb ish, stack temp); TRIMMED at IMP 0x634850..\n'),
    ),
    dict(
        name='fb_17',
        method='FreeBlock -[priorityBlockheadCannotPickup]',
        types='v8@0:4',
        start=6505756,
        end=6506020,
        disasm='disasm_worldtileloader_fb_17.txt',
        base_add=6505788,
        base_literal=6505992,
        boundary='ARM.exidx end 0x00634624 (listing bound); next ObjC IMP 0x00634624 FreeBlock -[shouldSaveEveryChangeInPosition]',
        selectors={
                 0x63460c: (15199936, 'release'),
                 0x63461c: (15199912, 'objectType'),
                 0x634620: (15199916, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={},
        ivars={
                 0x634604: (17157068, 'OBJC_IVAR_$_FreeBlock.priorityBlockhead', 136),
                 0x634610: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x634614: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x634618: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(6505756, 'push {fp, lr}'), (6506016, 'invalid')],
        calls=[(6505824, 'bl loc.imp.objc_msgSend'), (6505940, 'bl loc.imp.objc_msgSend'), (6505976, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[FreeBlock -[priorityBlockheadCannotPickup]] (imp 0x0063451c, 66w): -[priorityBlockheadCannotPickup] (0x63451c, 66w): [self->priorityBlockhead@136 release]; priorityBlockhead = nil; updateNeedsToBeSent@49 = YES; [self->dynamicWorld@8 dynamicWorldChangedAtPos:(self.pos.x@16, self.pos.y) objectType:[self objectType]] (sels 0xe7eea8/e7eeac) - the pickup reservation is dropped so any blockhead can take it..\n'),
    ),
    dict(
        name='fb_18',
        method='FreeBlock -[remoteUpdate:]',
        types='v12@0:4@8',
        start=6470292,
        end=6470872,
        disasm='disasm_worldtileloader_fb_18.txt',
        base_add=6470308,
        base_literal=6470868,
        boundary='ARM.exidx end 0x0062bcd8 (listing bound); next ObjC IMP 0x0062bcd8 FreeBlock -[hitLava]',
        selectors={
                 0x62bca4: (15200016, 'remoteUpdate:'),
                 0x62bcb4: (15199928, 'getBytes:length:'),
                 0x62bcd0: (15199936, 'release'),
        },
        imports={
                 0x62bca0: (17151900, 'objc_msgSendSuper2'),
                 0x62bcb0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x62bcac: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x62bcb8: (17157072, 'OBJC_IVAR_$_FreeBlock.hovers', 64),
                 0x62bcbc: (17157088, 'OBJC_IVAR_$_FreeBlock.yVelocity', 124),
                 0x62bcc4: (17157104, 'OBJC_IVAR_$_FreeBlock.xVelocity', 116),
                 0x62bcc8: (17157092, 'OBJC_IVAR_$_FreeBlock.fallSpeed', 72),
                 0x62bccc: (17157068, 'OBJC_IVAR_$_FreeBlock.priorityBlockhead', 136),
        },
        classes={
                 0x62bca8: (15252600, 'OBJC_CLASS_$_FreeBlock'),
        },
        instructions=[(6470292, 'push {r4, r5, fp, lr}'), (6470868, 'adceq r4, r3, r8, asr 32')],
        calls=[(6470384, 'blx lr'), (6470452, 'blx ip'), (6470780, 'blx r3')],
        branches=[(6470480, 'beq', 6470648), (6470684, 'beq', 6470808), (6470704, 'bne', 6470808), (6470708, 'b', 6470712)],
        semantics=('[FreeBlock -[remoteUpdate:]] (imp 0x0062ba94, 145w): -[remoteUpdate:] (0x62ba94, 145w, 4 branches, 3 call rows): objc_msgSendSuper2(self, remoteUpdate:data); if self->isNet@52 != 0: [data getBytes:buf length:0x28] (== fb_29\'s 0x28-byte update record) and fallSpeed@72 = (float)(s16)buf[0x20]/255.0f, xVelocity@116 = (s16)buf[0x22]/255, yVelocity@124 = (s16)buf[0x24]/255, hovers@64 = (s8)buf[0x26]; then if priorityBlockhead@136 != nil && record uid (buf+0x18 u64) == 0: [priorityBlockhead release]; priorityBlockhead = nil..\n'),
    ),
    dict(
        name='fb_19',
        method='FreeBlock -[removeFromMacroBlock]',
        types='v8@0:4',
        start=6461040,
        end=6461444,
        disasm='disasm_worldtileloader_fb_19.txt',
        base_add=6461056,
        base_literal=6461440,
        boundary='ARM.exidx end 0x00629804 (listing bound); next ObjC IMP 0x00629804 FreeBlock -[getSaveDict]',
        selectors={
                 0x6297e4: (15199932, 'removeFromMacroBlock'),
                 0x6297f8: (15199960, 'poleItemTaken:'),
        },
        imports={
                 0x6297e0: (17151900, 'objc_msgSendSuper2'),
                 0x6297f4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6297ec: (17157072, 'OBJC_IVAR_$_FreeBlock.hovers', 64),
                 0x6297f0: (17157048, 'OBJC_IVAR_$_FreeBlock.itemType', 56),
                 0x6297fc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x6297e8: (15252600, 'OBJC_CLASS_$_FreeBlock'),
        },
        instructions=[(6461040, 'push {r4, sl, fp, lr}'), (6461440, 'adceq r6, r3, ip, ror 8')],
        calls=[(6461124, 'blx ip'), (6461396, 'blx r3')],
        branches=[(6461160, 'beq', 6461400), (6461196, 'beq', 6461308), (6461232, 'beq', 6461308), (6461268, 'beq', 6461308), (6461304, 'bne', 6461400)],
        semantics=('[FreeBlock -[removeFromMacroBlock]] (imp 0x00629670, 101w): -[removeFromMacroBlock] (0x629670, 101w): objc_msgSendSuper2(self, removeFromMacroBlock) first (class cell 0xe8bc78); then if hovers@64 != 0 AND itemType@56 in {0x8e, 0x8c, 0x8f, 0x8d}: [self->dynamicWorld@8 poleItemTaken:itemType] (sel 0xe7eed8). The four consecutive item types are the "pole items" family (world custom rule \'poleItems\'; DynamicWorld.poleItemTakenTimes/poleItemTaken: recovered earlier E23/E30, registry key 0xfff34284)..\n'),
    ),
    dict(
        name='fb_20',
        method='FreeBlock -[setCreationSoundPlayTime:]',
        types='v12@0:4f8',
        start=6506844,
        end=6506920,
        disasm='disasm_worldtileloader_fb_20.txt',
        base_add=6506876,
        base_literal=6506916,
        boundary='ARM.exidx end 0x006349a8 (listing bound); next ObjC IMP 0x006349a8 FreeBlock -[soundType]',
        selectors={},
        imports={},
        ivars={
                 0x6349a0: (17157112, 'OBJC_IVAR_$_FreeBlock.creationSoundPlayTime', 144),
        },
        classes={},
        instructions=[(6506844, 'sub sp, sp, 0xc'), (6506916, 'adceq fp, r2, r0, ror r1')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[setCreationSoundPlayTime:]] (imp 0x0063495c, 19w): -[setCreationSoundPlayTime:] (0x63495c, 19w): setter of float creationSoundPlayTime@144 (vmov s0,r2; str), guarded by two dmb ish..\n'),
    ),
    dict(
        name='fb_21',
        method='FreeBlock -[setDataA:]',
        types='v12@0:4S8',
        start=6506236,
        end=6506308,
        disasm='disasm_worldtileloader_fb_21.txt',
        base_add=6506264,
        base_literal=6506304,
        boundary='ARM.exidx end 0x00634744 (listing bound); next ObjC IMP 0x00634744 FreeBlock -[dataB]',
        selectors={},
        imports={},
        ivars={
                 0x63473c: (17157080, 'OBJC_IVAR_$_FreeBlock.dataA', 60),
        },
        classes={},
        instructions=[(6506236, 'sub sp, sp, 0xc'), (6506304, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[setDataA:]] (imp 0x006346fc, 18w): -[setDataA:] (0x6346fc, 18w): setter of u16 dataA@60 (strh), dmb ish pair..\n'),
    ),
    dict(
        name='fb_22',
        method='FreeBlock -[setDataB:]',
        types='v12@0:4S8',
        start=6506368,
        end=6506440,
        disasm='disasm_worldtileloader_fb_22.txt',
        base_add=6506396,
        base_literal=6506436,
        boundary='ARM.exidx end 0x00634894; body trimmed at the next IMP 0x006347c8 FreeBlock -[subItems]',
        selectors={},
        imports={},
        ivars={
                 0x6347c0: (17157076, 'OBJC_IVAR_$_FreeBlock.dataB', 62),
        },
        classes={},
        instructions=[(6506368, 'sub sp, sp, 0xc'), (6506436, 'adceq fp, r2, r0, asr r3')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[setDataB:]] (imp 0x00634780, 18w): -[setDataB:] (0x634780, 18w): setter of u16 dataB@62 (strh), dmb ish pair; TRIMMED at IMP 0x6347c8..\n'),
    ),
    dict(
        name='fb_23',
        method='FreeBlock -[setHovers:]',
        types='v12@0:4c8',
        start=6506704,
        end=6506772,
        disasm='disasm_worldtileloader_fb_23.txt',
        base_add=6506732,
        base_literal=6506768,
        boundary='ARM.exidx end 0x006349a8; body trimmed at the next IMP 0x00634914 FreeBlock -[creationSoundPlayTime]',
        selectors={},
        imports={},
        ivars={
                 0x63490c: (17157072, 'OBJC_IVAR_$_FreeBlock.hovers', 64),
        },
        classes={},
        instructions=[(6506704, 'sub sp, sp, 0xc'), (6506768, 'adceq fp, r2, r0, lsl 4')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[setHovers:]] (imp 0x006348d0, 17w): -[setHovers:] (0x6348d0, 17w): setter of BOOL hovers@64 (strb), dmb ish pair; TRIMMED at IMP 0x634914..\n'),
    ),
    dict(
        name='fb_24',
        method='FreeBlock -[setItemType:]',
        types='v12@0:4i8',
        start=6506108,
        end=6506176,
        disasm='disasm_worldtileloader_fb_24.txt',
        base_add=6506136,
        base_literal=6506172,
        boundary='ARM.exidx end 0x006346c0 (listing bound); next ObjC IMP 0x006346c0 FreeBlock -[dataA]',
        selectors={},
        imports={},
        ivars={
                 0x6346b8: (17157048, 'OBJC_IVAR_$_FreeBlock.itemType', 56),
        },
        classes={},
        instructions=[(6506108, 'sub sp, sp, 0xc'), (6506172, 'adceq fp, r2, r4, asr r4')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[setItemType:]] (imp 0x0063467c, 17w): -[setItemType:] (0x63467c, 17w): setter of int itemType@56 (str), dmb ish pair..\n'),
    ),
    dict(
        name='fb_25',
        method='FreeBlock -[setSoundType:]',
        types='v12@0:4i8',
        start=6506980,
        end=6507048,
        disasm='disasm_worldtileloader_fb_25.txt',
        base_add=6507008,
        base_literal=6507044,
        boundary='ARM.exidx end 0x00634a28 (listing bound); next ObjC IMP 0x00637460 HungerUI -[loadResources]',
        selectors={},
        imports={},
        ivars={
                 0x634a20: (17157108, 'OBJC_IVAR_$_FreeBlock.soundType', 148),
        },
        classes={},
        instructions=[(6506980, 'sub sp, sp, 0xc'), (6507044, 'adceq fp, r2, ip, ror 1')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[setSoundType:]] (imp 0x006349e4, 17w): -[setSoundType:] (0x6349e4, 17w): setter of int soundType@148 (str), dmb ish pair..\n'),
    ),
    dict(
        name='fb_26',
        method='FreeBlock -[shouldSaveEveryChangeInPosition]',
        types='c8@0:4',
        start=6506020,
        end=6506048,
        disasm='disasm_worldtileloader_fb_26.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0063467c; body trimmed at the next IMP 0x00634640 FreeBlock -[itemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6506020, 'sub sp, sp, 8'), (6506044, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[shouldSaveEveryChangeInPosition]] (imp 0x00634624, 7w): -[shouldSaveEveryChangeInPosition] (0x634624, 7w): constant NO - movw r2,0; sxtb r0,r2; return; TRIMMED at IMP 0x634640..\n'),
    ),
    dict(
        name='fb_27',
        method='FreeBlock -[soundType]',
        types='i8@0:4',
        start=6506920,
        end=6506980,
        disasm='disasm_worldtileloader_fb_27.txt',
        base_add=6506944,
        base_literal=6506976,
        boundary='ARM.exidx end 0x006349e4 (listing bound); next ObjC IMP 0x006349e4 FreeBlock -[setSoundType:]',
        selectors={},
        imports={},
        ivars={
                 0x6349dc: (17157108, 'OBJC_IVAR_$_FreeBlock.soundType', 148),
        },
        classes={},
        instructions=[(6506920, 'sub sp, sp, 8'), (6506976, 'adceq fp, r2, ip, lsr 2')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[soundType]] (imp 0x006349a8, 15w): -[soundType] (0x6349a8, 15w): offset-cell getter of int soundType@148 with dmb ish..\n'),
    ),
    dict(
        name='fb_28',
        method='FreeBlock -[subItems]',
        types='@8@0:4',
        start=6506440,
        end=6506508,
        disasm='disasm_worldtileloader_fb_28.txt',
        base_add=6506464,
        base_literal=6506504,
        boundary='ARM.exidx end 0x00634894; body trimmed at the next IMP 0x0063480c FreeBlock -[priorityBlockhead]',
        selectors={},
        imports={},
        ivars={
                 0x634804: (17157084, 'OBJC_IVAR_$_FreeBlock.subItems', 112),
        },
        classes={},
        instructions=[(6506440, 'sub sp, sp, 0xc'), (6506504, 'adceq fp, r2, ip, lsl 6')],
        calls=[],
        branches=[],
        semantics=('[FreeBlock -[subItems]] (imp 0x006347c8, 17w): -[subItems] (0x6347c8, 17w): offset-cell getter of the object ivar subItems@112 (dmb ish, stack temp); TRIMMED at IMP 0x63480c..\n'),
    ),
    dict(
        name='fb_29',
        method='FreeBlock -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=6464700,
        end=6465264,
        disasm='disasm_worldtileloader_fb_29.txt',
        base_add=6464716,
        base_literal=6465260,
        boundary='ARM.exidx end 0x0062a6f0 (listing bound); next ObjC IMP 0x0062a6f0 FreeBlock -[creationNetDataForClient:]',
        selectors={
                 0x62a6b8: (15199996, 'dynamicObjectNetData'),
                 0x62a6d8: (15200000, 'dataWithBytes:length:'),
                 0x62a6e8: (15199992, 'uniqueID'),
        },
        imports={
                 0x62a6d4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x62a6bc: (17157072, 'OBJC_IVAR_$_FreeBlock.hovers', 64),
                 0x62a6c0: (17157092, 'OBJC_IVAR_$_FreeBlock.fallSpeed', 72),
                 0x62a6cc: (17157104, 'OBJC_IVAR_$_FreeBlock.xVelocity', 116),
                 0x62a6d0: (17157088, 'OBJC_IVAR_$_FreeBlock.yVelocity', 124),
                 0x62a6e0: (17157068, 'OBJC_IVAR_$_FreeBlock.priorityBlockhead', 136),
        },
        classes={
                 0x62a6dc: (15245752, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6464700, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6465260, 'adceq r5, r3, r0, lsr 12')],
        calls=[(6464952, 'bl loc.imp.objc_msgSend_stret'), (6464988, 'bl sym.imp.memset'), (6465140, 'bl loc.imp.objc_msgSend'), (6465188, 'blx ip')],
        branches=[(6464936, 'beq', 6464960), (6464956, 'b', 6464992)],
        semantics=('[FreeBlock -[updateNetDataForClient:]] (imp 0x0062a4bc, 141w): -[updateNetDataForClient:] (0x62a4bc, 141w): builds a 0x28-byte record at sp+0x48 and returns a NEW [NSMutableData dataWithBytes:length:0x28] (sel 0xe7ef00); the (data) argument is spilled to [fp,-0x24] and never read. Record: +0x00..0x17 [self dynamicObjectNetData] (stret 0x18, sel 0xe7eefc; memset 0 when self nil); +0x18..0x1f [priorityBlockhead@136 uniqueID] u64 (lo@+0x18 hi@+0x1c, nil->0; sel 0xe7eef8); +0x20 (u16)(fallSpeed@72*255.0f) (0x437f0000 @0x62a6c8); +0x22 (u16)(xVelocity@116*255); +0x24 (u16)(yVelocity@124*255); +0x26 hovers@64 (u8). Same 0x28 convention as Boat bo_08; consumed by fb_18 remoteUpdate:..\n'),
    ),
    dict(
        name='fb_30',
        method='FreeBlock -[updatePosition:]',
        types='v16@0:4{?=ii}8',
        start=6449472,
        end=6449768,
        disasm='disasm_worldtileloader_fb_30.txt',
        base_add=6449516,
        base_literal=6449740,
        boundary='ARM.exidx end 0x00626a68 (listing bound); next ObjC IMP 0x00626a68 FreeBlock -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x626a54: (15199868, 'updatePosition:'),
                 0x626a60: (15199872, 'freeblockPositionChanged:oldPos:'),
        },
        imports={},
        ivars={
                 0x626a48: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x626a58: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x626a50: (15252600, 'OBJC_CLASS_$_FreeBlock'),
        },
        instructions=[(6449472, 'push {fp, lr}'), (6449764, 'andeq r0, r0, r0')],
        calls=[(6449604, 'bl loc.imp.objc_msgSendSuper2'), (6449724, 'bl loc.imp.objc_msgSend')],
        branches=[(6449620, 'bne', 6449640), (6449636, 'beq', 6449728)],
        semantics=('[FreeBlock -[updatePosition:]] (imp 0x00626940, 74w): -[updatePosition:] (0x626940, 74w): saves old pos from self->pos@16 (pre-index load), calls objc_msgSendSuper2(self, updatePosition:newPos) with the {self, FreeBlock, {x,y}} struct (sel 0xe7ee7c), then when newPos != oldPos: [self->dynamicWorld@8 freeblockPositionChanged:self oldPos:(oldX,oldY)] (sel 0xe7ee80; r2=self, r3=oldX, [sp]=oldY)..\n'),
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
        'batch': 'FreeBlock (E152): the dropped-item entity; 31 bodies',
        'claim': ('the dropped-item entity (drop physics, light contribution, pickup)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'freeblock.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale freeblock.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
