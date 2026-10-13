#!/usr/bin/env python3
"""Hash-gated recovery of the Sign (E147).

Sign lands: the batch sweeps sign surface:
36 bodies, 6132 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/SIGN.md for the prose and boundaries.
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
    'bl 0x5fae74': 0x005fae74,
    'bl 0x5fb680': 0x005fb680,
    'bl 0x5fbd64': 0x005fbd64,
    'bl 0x5fc370': 0x005fc370,
    'bl 0x5fc39c': 0x005fc39c,
    'bl 0x5ff1f8': 0x005ff1f8,
    'bl 0x5ff3e0': 0x005ff3e0,
    'bl 0x5ff9a0': 0x005ff9a0,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.drawShaderQuad': 0x007c43dc,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_glActiveTexture': 0x001c2dc8,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisable': 0x001c2c48,
    'bl sym.imp.__wrap_glEnable': 0x001c2b04,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.paintedIndexForImageIndex_int_': 0x00a15e28,
    'bl sym.popDepthMaskState': 0x007c57ec,
    'bl sym.pushDepthMaskState': 0x007c55e4,
    'bl sym.signConnectionTypeAndOffsetForPos_intpair__int__World__int_': 0x005f85a0,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
}

SPECS = [
    dict(
        name='sg_00',
        method='Sign -[actionTitle]',
        types='@8@0:4',
        start=6294420,
        end=6294468,
        disasm='disasm_worldtileloader_sg_00.txt',
        base_add=6294428,
        base_literal=6294464,
        boundary='ARM.exidx end 0x00600be0; body trimmed at the next IMP 0x00600bc4 Sign -[requiresHumanInteraction]',
        selectors={},
        imports={
                 0x600bbc: (16245736, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(6294420, 'sub sp, sp, 8'), (6294464, 'adceq lr, r5, r0, asr pc')],
        calls=[],
        branches=[],
        semantics=('[Sign -[actionTitle]] (imp 0x00600b94, 12w): -[actionTitle] (0x600b94, 12w, trimmed at next IMP): returns the static CFString "CHANGE SIGN" @0xF7E3E8 (flags 0x7c8, len 11) via the Apportable literal pattern (add r2,pc,r2 -> PIC base 0x105FAF4; delta cell 0x600bbc). A hardcoded action title, NOT [self title]..\n'),
    ),
    dict(
        name='sg_01',
        method='Sign -[canBeUsedByBlockhead:]',
        types='c12@0:4@8',
        start=6295332,
        end=6295812,
        disasm='disasm_worldtileloader_sg_01.txt',
        base_add=6295348,
        base_literal=6295808,
        boundary='ARM.exidx end 0x00601104 (listing bound); next ObjC IMP 0x00601104 Sign -[interactionRenderItemType]',
        selectors={
                 0x6010dc: (15199332, 'isAdmin'),
                 0x6010e4: (15199336, 'isClientBlockheadBeingControlledByServer'),
                 0x6010ec: (15199340, 'canBeUsedByBlockhead:'),
                 0x6010f8: (15199232, 'isEqualToString:'),
                 0x6010fc: (15199344, 'localNetID'),
        },
        imports={
                 0x6010d8: (17151904, 'objc_msgSend'),
                 0x6010e8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x6010e0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x6010f4: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0x6010f0: (15252588, 'OBJC_CLASS_$_Sign'),
        },
        instructions=[(6295332, 'push {r4, sl, fp, lr}'), (6295808, 'invalid')],
        calls=[(6295412, 'blx ip'), (6295468, 'blx r2'), (6295564, 'blx r3'), (6295704, 'blx lr'), (6295740, 'blx r3')],
        branches=[(6295424, 'beq', 6295496), (6295480, 'bne', 6295496), (6295492, 'b', 6295756), (6295588, 'beq', 6295748), (6295628, 'beq', 6295748)],
        semantics=('[Sign -[canBeUsedByBlockhead:]] (imp 0x00600f24, 120w): -[canBeUsedByBlockhead:] (0x600f24, 120w, 5br, 5c): `if ([self.world@4 isAdmin] && ![bh isClientBlockheadBeingControlledByServer]) return YES;` else `BOOL ok = [super canBeUsedByBlockhead:bh]` (objc_msgSendSuper2, currentClass=Sign); `if (ok && self.ownerID@36 != nil) ok = [[bh localNetID] isEqualToString:self.ownerID]; return ok;`..\n'),
    ),
    dict(
        name='sg_02',
        method='Sign -[connectionType]',
        types='i8@0:4',
        start=6296280,
        end=6296340,
        disasm='disasm_worldtileloader_sg_02.txt',
        base_add=6296304,
        base_literal=6296336,
        boundary='ARM.exidx end 0x00601314 (listing bound); next ObjC IMP 0x00601af0 JoinWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:]',
        selectors={},
        imports={},
        ivars={
                 0x60130c: (17156852, 'OBJC_IVAR_$_Sign.connectionType', 112),
        },
        classes={},
        instructions=[(6296280, 'sub sp, sp, 8'), (6296336, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[Sign -[connectionType]] (imp 0x006012d8, 15w): -[connectionType] (0x6012d8, 15w): plain ivar getter `return self.connectionType@112` (int; O0 unloc chain + dmb ish)..\n'),
    ),
    dict(
        name='sg_03',
        method='Sign -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=6272116,
        end=6272640,
        disasm='disasm_worldtileloader_sg_03.txt',
        base_add=6272132,
        base_literal=6272636,
        boundary='ARM.exidx end 0x005fb680 (listing bound); next ObjC IMP 0x005fb7ec Sign -[dealloc]',
        selectors={
                 0x5fb658: (15199184, 'interactionObjectCreationNetData'),
                 0x5fb660: (15199200, 'appendData:'),
                 0x5fb664: (15199196, 'gzipDeflate'),
                 0x5fb668: (15199192, 'netDataExtraDataDict'),
                 0x5fb66c: (15199188, 'dataWithBytes:length:'),
        },
        imports={
                 0x5fb65c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5fb674: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
                 0x5fb678: (17156852, 'OBJC_IVAR_$_Sign.connectionType', 112),
        },
        classes={
                 0x5fb670: (15245664, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6272116, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6272636, 'adceq r4, r6, r8, ror 12')],
        calls=[(6272208, 'bl loc.imp.objc_msgSend_stret'), (6272244, 'bl sym.imp.memset'), (6272372, 'bl sym.imp.memcpy'), (6272460, 'blx ip'), (6272484, 'blx r2'), (6272496, 'bl 0x5fb680'), (6272556, 'blx lr'), (6272584, 'blx r3')],
        branches=[(6272192, 'beq', 6272216), (6272212, 'b', 6272248)],
        semantics=('[Sign -[creationNetDataForClient:]] (imp 0x005fb474, 131w): -[creationNetDataForClient:] (0x5fb474, 131w, 2br, 8c): builds the wire blob: `[self interactionObjectCreationNetData]` (sret, 0x28 bytes; self==nil -> memset 0x28) then memcpy to the stack buffer; `buf[0x28]=(char)self.connectionType@112; buf[0x29]=(char)self.offsetType@116` (strb); `d=[NSMutableData dataWithBytes:buf length:0x30]` (movw ip,#0x30, byte-verified 0xe300c030); `extra=plistData([self netDataExtraDataDict])` (local helper @0x5fb680: NSPropertyListSerialization dataWithPropertyList:format:100/XML options:0 in @try/@catch + NSLog); `[d appendData:[extra gzipDeflate]]`; return d. client arg stored but never read; only 0x2A of the 0x30 blob bytes written explicitly..\n'),
    ),
    dict(
        name='sg_04',
        method='Sign -[dealloc]',
        types='v8@0:4',
        start=6273004,
        end=6273260,
        disasm='disasm_worldtileloader_sg_04.txt',
        base_add=6273020,
        base_literal=6273256,
        boundary='ARM.exidx end 0x005fb8ec (listing bound); next ObjC IMP 0x005fb8ec Sign -[removeFromMacroBlock]',
        selectors={
                 0x5fb8d0: (15199208, 'dealloc'),
                 0x5fb8dc: (15199204, 'release'),
        },
        imports={
                 0x5fb8cc: (17151900, 'objc_msgSendSuper2'),
                 0x5fb8d8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5fb8e0: (17156856, 'OBJC_IVAR_$_Sign.bitmapString', 104),
                 0x5fb8e4: (17156836, 'OBJC_IVAR_$_Sign.text', 100),
        },
        classes={
                 0x5fb8d4: (15252588, 'OBJC_CLASS_$_Sign'),
        },
        instructions=[(6273004, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6273256, 'invalid')],
        calls=[(6273140, 'blx r5'), (6273176, 'blx r3'), (6273216, 'blx r2')],
        branches=[],
        semantics=('[Sign -[dealloc]] (imp 0x005fb7ec, 64w): -[dealloc] (0x5fb7ec, 64w, 3c): `[self.text@100 release]; [self.bitmapString@104 release]; objc_msgSendSuper2(&super{self, Sign}, @selector(dealloc));`. tileDestructTexture@108 NOT released; no ivar nil-ed..\n'),
    ),
    dict(
        name='sg_05',
        method='Sign -[destroyItemType]',
        types='i8@0:4',
        start=6294344,
        end=6294372,
        disasm='disasm_worldtileloader_sg_05.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00600be0; body trimmed at the next IMP 0x00600b64 Sign -[title]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6294344, 'sub sp, sp, 8'), (6294368, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Sign -[destroyItemType]] (imp 0x00600b48, 7w): -[destroyItemType] (0x600b48, 7w): `return 0xa3` (163) - item id dropped on destroy..\n'),
    ),
    dict(
        name='sg_06',
        method='Sign -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=6277872,
        end=6287864,
        disasm='disasm_worldtileloader_sg_06.txt',
        base_add=6277900,
        base_literal=6281652,
        boundary='ARM.exidx end 0x005ff1f8 (listing bound); next ObjC IMP 0x005ffb58 Sign -[worldChanged:]',
        selectors={
                 0x5fd9c4: (15199264, 'worldWidthMacro'),
                 0x5fe19c: (15199268, 'macroTiles'),
                 0x5fe1a8: (15199272, 'program'),
                 0x5fe1ac: (15199276, 'uniformLocations'),
                 0x5fe1b0: (15199280, 'objectAtIndex:'),
                 0x5fe1b4: (15199124, 'intValue'),
                 0x5fe1b8: (15199064, 'interactionObjectType'),
                 0x5fe1c4: (15199284, 'dayColor'),
                 0x5fe1c8: (15199288, 'name'),
                 0x5fe1d4: (15199292, 'roundedTranslation'),
                 0x5ff1d8: (15199276, 'uniformLocations'),
                 0x5ff1dc: (15199280, 'objectAtIndex:'),
                 0x5ff1e0: (15199124, 'intValue'),
                 0x5ff1f0: (15199296, 'setColor:'),
                 0x5ff1f4: (15199300, 'renderWithProjectionMatrix:modelViewMatrix:'),
        },
        imports={
                 0x5fe198: (17151904, 'objc_msgSend'),
                 0x5ff1d0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5fd9b8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5fd9c0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x5fded0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x5fe1a0: (17156776, 'OBJC_IVAR_$_InteractionObject.shader', 60),
                 0x5fe1bc: (17156852, 'OBJC_IVAR_$_Sign.connectionType', 112),
                 0x5fe1c0: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x5fe1cc: (17156844, 'OBJC_IVAR_$_InteractionObject.texture', 64),
                 0x5fe1d0: (17156840, 'OBJC_IVAR_$_Sign.tileDestructTexture', 108),
                 0x5fe1dc: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
                 0x5ff1d4: (17156776, 'OBJC_IVAR_$_InteractionObject.shader', 60),
                 0x5ff1e4: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
                 0x5ff1e8: (17156856, 'OBJC_IVAR_$_Sign.bitmapString', 104),
        },
        classes={},
        instructions=[(6277872, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6287860, 'invalid')],
        calls=[(6278548, 'bl loc.imp.objc_msgSend'), (6278572, 'bl sym.imp.__aeabi_idiv'), (6278640, 'bl loc.imp.objc_msgSend'), (6278760, 'bl loc.imp.objc_msgSend'), (6278776, 'bl sym.imp.__aeabi_idiv'), (6278844, 'bl loc.imp.objc_msgSend'), (6278968, 'bl loc.imp.objc_msgSend'), (6278992, 'bl sym.imp.__aeabi_idiv'), (6279060, 'bl loc.imp.objc_msgSend'), (6279180, 'bl loc.imp.objc_msgSend'), (6279196, 'bl sym.imp.__aeabi_idiv'), (6279264, 'bl loc.imp.objc_msgSend'), (6279528, 'bl method.Vector2.operator_float__'), (6279588, 'bl loc.imp.objc_msgSend'), (6279612, 'bl sym.imp.__aeabi_idiv'), (6279700, 'bl loc.imp.objc_msgSend'), (6279732, 'bl method.Vector2.operator_float__'), (6279780, 'bl method.Vector2.operator_float__'), (6279844, 'bl loc.imp.objc_msgSend'), (6279860, 'bl sym.imp.__aeabi_idiv'), (6279948, 'bl loc.imp.objc_msgSend'), (6279980, 'bl method.Vector2.operator_float__'), (6280112, 'blx r2'), (6280156, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (6280232, 'bl loc.imp.objc_msgSend'), (6280236, 'bl sym.imp.__wrap_glUseProgram'), (6280272, 'bl loc.imp.objc_msgSend'), (6280308, 'bl loc.imp.objc_msgSend'), (6280332, 'bl loc.imp.objc_msgSend'), (6280344, 'bl sym.imp.__wrap_glUniform1i'), (6280376, 'bl loc.imp.objc_msgSend'), (6280396, 'bl loc.imp.objc_msgSend'), (6280412, 'bl loc.imp.objc_msgSend'), (6280420, 'bl sym.imp.__wrap_glUniform1i'), (6280440, 'bl loc.imp.objc_msgSend'), (6280784, 'bl method.Vector.Vector_float__float__float__float_'), (6280832, 'bl sym.paintedIndexForImageIndex_int_'), (6280884, 'bl 0x5fbd64'), (6280996, 'bl loc.imp.objc_msgSend_stret'), (6281036, 'bl sym.imp.memset'), (6281480, 'bl method.Vector.Vector_float__float__float_'), (6281500, 'bl method.Vector.operator_float__'), (6281524, 'bl method.Vector.operator_float__'), (6281548, 'bl method.Vector.operator_float__'), (6281764, 'bl method.Vector.Vector_float__float__float__float_'), (6281836, 'blx r2'), (6281856, 'bl sym.imp.__wrap_glBindTexture'), (6281864, 'bl sym.imp.__wrap_glActiveTexture'), (6281940, 'blx r3'), (6281960, 'bl sym.imp.__wrap_glBindTexture'), (6282092, 'blx r6'), (6282112, 'blx r3'), (6282128, 'blx r2'), (6282144, 'bl method.Vector.operator_float__'), (6282168, 'bl method.Vector.operator_float__'), (6282192, 'bl method.Vector.operator_float__'), (6282216, 'bl method.Vector.operator_float__'), (6282260, 'bl sym.imp.__wrap_glUniform4f'), (6282392, 'blx r6'), (6282412, 'blx r3'), (6282428, 'blx r2'), (6282444, 'bl method.Vector.operator_float__'), (6282468, 'bl method.Vector.operator_float__'), (6282492, 'bl method.Vector.operator_float__'), (6282516, 'bl method.Vector.operator_float__'), (6282560, 'bl sym.imp.__wrap_glUniform4f'), (6282692, 'blx r6'), (6282712, 'blx r3'), (6282728, 'blx r2'), (6282744, 'bl method.Vector.operator_float__'), (6282768, 'bl method.Vector.operator_float__'), (6282792, 'bl method.Vector.operator_float__'), (6282816, 'bl method.Vector.operator_float__'), (6282860, 'bl sym.imp.__wrap_glUniform4f'), (6282936, 'bl loc.imp.objc_msgSend_stret'), (6282996, 'bl sym.imp.memset'), (6283052, 'bl loc.imp.objc_msgSend'), (6283072, 'bl loc.imp.objc_msgSend'), (6283088, 'bl loc.imp.objc_msgSend'), (6283108, 'bl method.Vector2.operator_float__'), (6283128, 'bl method.Vector2.operator_float__'), (6283152, 'bl method.Vector2.operator_float__'), (6283168, 'bl method.Vector2.operator_float__'), (6283216, 'bl sym.imp.__wrap_glUniform4f'), (6283352, 'bl method.Vector2.operator_float__'), (6283368, 'bl method.Vector2.operator_float__'), (6283584, 'bl 0x5ff1f8'), (6283592, 'bl sym.imp.__wrap_glEnable'), (6283604, 'bl sym.pushDepthMaskState'), (6284708, 'bl 0x5ff3e0'), (6284840, 'blx r3'), (6284860, 'blx r3'), (6284876, 'blx r2'), (6284908, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (6285020, 'bl sym.drawShaderQuad'), (6285172, 'bl sym.imp.__modsi3'), (6285188, 'bl sym.imp.__aeabi_idiv'), (6285536, 'bl sym.drawShaderQuad'), (6285548, 'bl sym.imp.__wrap_glBindTexture'), (6285556, 'bl sym.imp.__wrap_glActiveTexture'), (6285612, 'bl method.Vector.operator_float__'), (6285668, 'bl method.Vector.operator_float__'), (6285700, 'bl method.Vector.operator_float__'), (6285744, 'bl method.Vector.operator_float__'), (6285776, 'bl method.Vector.operator_float__'), (6285820, 'bl method.Vector.operator_float__'), (6285872, 'bl method.Vector.Vector_float__float__float_'), (6285924, 'bl method.Vector.operator_float__'), (6285956, 'bl method.Vector.operator_float__'), (6285988, 'bl method.Vector.operator_float__'), (6286068, 'bl 0x5fc39c'), (6286116, 'bl loc.imp.objc_msgSend'), (6286464, 'bl 0x5ff1f8'), (6286932, 'bl 0x5ff9a0'), (6287800, 'bl loc.imp.objc_msgSend'), (6287808, 'bl sym.imp.__wrap_glDisable'), (6287812, 'bl sym.popDepthMaskState')],
        branches=[(6278584, 'blt', 6278672), (6278668, 'b', 6278876), (6278788, 'bge', 6278872), (6278872, 'b', 6278876), (6279004, 'blt', 6279092), (6279088, 'b', 6279296), (6279208, 'bge', 6279292), (6279292, 'b', 6279296), (6279332, 'blt', 6279456), (6279372, 'bgt', 6279456), (6279412, 'blt', 6279456), (6279452, 'ble', 6279460), (6279456, 'b', 6287816), (6279636, 'ble', 6279756), (6279752, 'b', 6280004), (6279884, 'bpl', 6280000), (6280000, 'b', 6280004), (6280176, 'bne', 6280184), (6280180, 'b', 6287816), (6280524, 'bhi', 6280736), (6280604, 'b', 6280740), (6280644, 'b', 6280740), (6280692, 'b', 6280740), (6280732, 'b', 6280740), (6280736, 'b', 6280740), (6280824, 'beq', 6280920), (6280976, 'beq', 6281004), (6281000, 'b', 6281040), (6281160, 'bpl', 6281180), (6281176, 'b', 6281192), (6281236, 'bpl', 6281256), (6281252, 'b', 6281268), (6281312, 'ble', 6281384), (6281632, 'bpl', 6281696), (6281648, 'b', 6281708), (6282920, 'beq', 6282968), (6282940, 'b', 6283000), (6283640, 'bne', 6283768), (6283656, 'b', 6283820), (6283800, 'bne', 6283816), (6283816, 'b', 6283820), (6285036, 'beq', 6285540), (6285040, 'b', 6285104), (6285352, 'bne', 6285384), (6285596, 'beq', 6287804)],
        semantics=('[Sign -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x005fcaf0, 2498w): -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] (0x5fcaf0, 2498w, 45br, 117c) [CENSUS - straight-line, no back edges; 2336-byte frame (sub sp,#0x920; bic sp,#0xf)]: O0 arg spill (arg3 preserved via vmov s0 -> [+0x260]); camera/world clamp via [world worldWidthMacro]x32 + __aeabi_idiv x7 + Vector2 ops, window rejects -> early return (0x5ff1c8); `[self.world tileAtWorldPosition:...MacroTile:...]` nil -> return; `[self.shader@60 use]` -> glUseProgram; `[[shader uniformLocations] objectAtIndex:N] intValue]` -> glUniform1i x2; image-index switch on self.connectionType@112-1 (5-way jump table @0x5fd564: 1->(interactionObjectType==8 ? 0x28a:0xb2), 2->0x28e, 3->0x28c + destruct flag, 4->0x28c; base index flag?0x288:0xb0) -> paintedIndexForImageIndex(int); UV math /1024.0f clamp <=1, scale 1/(0.3+[+0x1e4]), /255.0f; 3 texture bind/activates (texture@64 unit0; tileDestructTexture@108 unit1/unit2) + glUniform4f x4 (color vectors); mvp matrix built by local helper 0x5ff3e0 (@sp+0x6d0) -> glUniformMatrix4fv(loc,1,0,ptr); glEnable(GL_BLEND)+pushDepthMaskState; positions = world*0.03125 (1/32) + 1/2048 offsets (f64), +/-5.0f flip adjust; drawShaderQuad #1 (10 float args from [+0xdc..+0xf0]); if destruct flag @sp+0x863: frame via __modsi3(180)/__aeabi_idiv(32) + f64 consts 1/2048, 1/1024, 5/4096, quad edge rotate when offsetType@116==1, v edges -= 0.0009765625, drawShaderQuad #2 (destruct overlay strip); unbind textures (glBindTexture(2D,0); glActiveTexture(GL_TEXTURE0)); if (self.bitmapString@104) { Vector3 light (byte/255 lerp; f64 0.9/0.2 consts) -> [bitmapString setColor:] -> local uniform helpers 0x5ff1f8/0x5ff9a0 -> [bitmapString renderWithProjectionMatrix:modelViewMatrix:] }; glDisable(GL_BLEND)+popDepthMaskState. Constants: 1024.0f @0x5fd9d4, 0.3f @0x5fd9d8, 255.0f @0x5fd9dc; f64 0.03125 / 1/2048 / -1/1024 @0x5fe1e0-f0..\n'),
    ),
    dict(
        name='sg_07',
        method='Sign -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=6292800,
        end=6292828,
        disasm='disasm_worldtileloader_sg_07.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00600578; body trimmed at the next IMP 0x0060055c Sign -[freeBlockCreationDataB]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6292800, 'sub sp, sp, 8'), (6292824, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Sign -[freeBlockCreationDataA]] (imp 0x00600540, 7w): -[freeBlockCreationDataA] (0x600540, 7w): `return 0` (u16)..\n'),
    ),
    dict(
        name='sg_08',
        method='Sign -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=6292828,
        end=6292856,
        disasm='disasm_worldtileloader_sg_08.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00600578 (listing bound); next ObjC IMP 0x00600578 Sign -[remove:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6292828, 'sub sp, sp, 8'), (6292852, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Sign -[freeBlockCreationDataB]] (imp 0x0060055c, 7w): -[freeBlockCreationDataB] (0x60055c, 7w): `return 0` (u16)..\n'),
    ),
    dict(
        name='sg_09',
        method='Sign -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=6292724,
        end=6292800,
        disasm='disasm_worldtileloader_sg_09.txt',
        base_add=6292740,
        base_literal=6292796,
        boundary='ARM.exidx end 0x00600540 (listing bound); next ObjC IMP 0x00600540 Sign -[freeBlockCreationDataA]',
        selectors={
                 0x600538: (15199164, 'getSaveDict'),
        },
        imports={
                 0x600534: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6292724, 'push {fp, lr}'), (6292796, 'adceq pc, r5, r8, ror 11')],
        calls=[(6292776, 'blx r3')],
        branches=[],
        semantics=('[Sign -[freeBlockCreationSaveDict]] (imp 0x006004f4, 19w): -[freeBlockCreationSaveDict] (0x6004f4, 19w, 1c): pure forward `return [self getSaveDict]` (objc_msgSend to the getSaveDict selref @0x600538)..\n'),
    ),
    dict(
        name='sg_10',
        method='Sign -[freeblockCreationItemType]',
        types='i8@0:4',
        start=6292648,
        end=6292724,
        disasm='disasm_worldtileloader_sg_10.txt',
        base_add=6292664,
        base_literal=6292720,
        boundary='ARM.exidx end 0x00600540; body trimmed at the next IMP 0x006004f4 Sign -[freeBlockCreationSaveDict]',
        selectors={
                 0x6004ec: (15199308, 'destroyItemType'),
        },
        imports={
                 0x6004e8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6292648, 'push {fp, lr}'), (6292720, 'adceq pc, r5, r4, lsr r6')],
        calls=[(6292700, 'blx r3')],
        branches=[],
        semantics=('[Sign -[freeblockCreationItemType]] (imp 0x006004a8, 19w): -[freeblockCreationItemType] (0x6004a8, 19w, 1c): pure forward `return [self destroyItemType]`..\n'),
    ),
    dict(
        name='sg_11',
        method='Sign -[initSubDerivedItems]',
        types='v8@0:4',
        start=6265600,
        end=6267320,
        disasm='disasm_worldtileloader_sg_11.txt',
        base_add=6265616,
        base_literal=6267316,
        boundary='ARM.exidx end 0x005fa1b8 (listing bound); next ObjC IMP 0x005fa1b8 Sign -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]',
        selectors={
                 0x5fa144: (15199092, 'textureNamed:withAlpha:'),
                 0x5fa154: (15199088, 'textureNamed:'),
                 0x5fa160: (15199084, 'shaderNamed:attributes:uniforms:'),
                 0x5fa180: (15199080, 'arrayWithObjects:'),
                 0x5fa190: (15199096, 'updateBitmapString'),
                 0x5fa1a4: (15199100, 'worldContentsChangedAtPos:'),
        },
        imports={
                 0x5fa138: (16245608, '__CFConstantStringClassReference'),
                 0x5fa13c: (16245624, '__CFConstantStringClassReference'),
                 0x5fa140: (17151904, 'objc_msgSend'),
                 0x5fa150: (16245592, '__CFConstantStringClassReference'),
                 0x5fa15c: (16245432, '__CFConstantStringClassReference'),
                 0x5fa164: (16245480, '__CFConstantStringClassReference'),
                 0x5fa168: (16245496, '__CFConstantStringClassReference'),
                 0x5fa16c: (16245512, '__CFConstantStringClassReference'),
                 0x5fa170: (16245528, '__CFConstantStringClassReference'),
                 0x5fa174: (16245544, '__CFConstantStringClassReference'),
                 0x5fa178: (16245560, '__CFConstantStringClassReference'),
                 0x5fa17c: (16245576, '__CFConstantStringClassReference'),
                 0x5fa188: (16245448, '__CFConstantStringClassReference'),
                 0x5fa18c: (16245464, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5fa130: (17156836, 'OBJC_IVAR_$_Sign.text', 100),
                 0x5fa134: (17156840, 'OBJC_IVAR_$_Sign.tileDestructTexture', 108),
                 0x5fa148: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x5fa14c: (17156844, 'OBJC_IVAR_$_InteractionObject.texture', 64),
                 0x5fa158: (17156776, 'OBJC_IVAR_$_InteractionObject.shader', 60),
                 0x5fa194: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x5fa198: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5fa19c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5fa1a8: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
        },
        classes={
                 0x5fa184: (15245652, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(6265600, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6267316, 'invalid')],
        calls=[(6266024, 'blx r6'), (6266112, 'blx r8'), (6266156, 'blx lr'), (6266216, 'blx ip'), (6266280, 'blx ip'), (6266376, 'blx r2'), (6266452, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6266588, 'bl loc.imp.objc_msgSend'), (6266708, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6266844, 'bl sym.makeIntpair_int__int_'), (6266872, 'bl loc.imp.objc_msgSend'), (6266996, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6267132, 'bl sym.makeIntpair_int__int_'), (6267160, 'bl loc.imp.objc_msgSend')],
        branches=[(6266332, 'beq', 6266380), (6266472, 'beq', 6266596), (6266488, 'bne', 6266592), (6266592, 'b', 6266596), (6266628, 'bne', 6266884), (6266728, 'beq', 6266880), (6266744, 'bne', 6266876), (6266876, 'b', 6266880), (6266880, 'b', 6267176), (6266916, 'bne', 6267172), (6267016, 'beq', 6267168), (6267032, 'bne', 6267164), (6267164, 'b', 6267168), (6267168, 'b', 6267172), (6267172, 'b', 6267176)],
        semantics=('[Sign -[initSubDerivedItems]] (imp 0x005f9b00, 430w): -[initSubDerivedItems] (0x5f9b00, 430w, 15br, 14c): attrs=[NSArray arrayWithObjects:@"position",@"texCoord",nil]; uniforms=[NSArray arrayWithObjects:@"mvp_matrix",@"texture",@"destruct_texture",@"artificialLight",@"daylight",@"lightPosition",@"paintColor",nil] (CFSTRs 0xF7E2B8..0xF7E348); `self.shader@60=[self.cache@32 shaderNamed:@"WorldObjectNewLighting" attributes: uniforms:]`; `self.texture@64=[self.cache textureNamed:@"TileMap.png"]`; `self.tileDestructTexture@108=[self.cache textureNamed:@"TileDestruct.png" withAlpha:@"TileReflect.png"]`; `if (self.text@100) [self updateBitmapString]`; then the tile marker at self.pos (unconditional): t=[self.world tileAtWorldPositionLoaded:pos.x,pos.y]; if(t && !t[0xb]) {t[0xb]=0x30; [self.dynamicWorld@8 worldContentsChangedAtPos:self.pos]}; offsetType==1 -> same at pos.x+1, ==2 -> pos.x-1 (pair via makeIntpair). Here worldContentsChanged is gated on the store actually happening..\n'),
    ),
    dict(
        name='sg_12',
        method='Sign -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]',
        types='@48@0:4@8@12{?=ii}16@24@28c32@36@40@44',
        start=6267320,
        end=6268392,
        disasm='disasm_worldtileloader_sg_12.txt',
        base_add=6267336,
        base_literal=6268388,
        boundary='ARM.exidx end 0x005fa5e8 (listing bound); next ObjC IMP 0x005fa5e8 Sign -[interactionObjectType]',
        selectors={
                 0x5fa5b0: (15199104, 'initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:'),
                 0x5fa5bc: (15199108, 'objectForKey:'),
                 0x5fa5c8: (15199112, 'retain'),
                 0x5fa5dc: (15199116, 'initSubDerivedItems'),
        },
        imports={
                 0x5fa5c4: (16245640, '__CFConstantStringClassReference'),
                 0x5fa5d8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5fa5b4: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
                 0x5fa5b8: (17156852, 'OBJC_IVAR_$_Sign.connectionType', 112),
                 0x5fa5cc: (17156836, 'OBJC_IVAR_$_Sign.text', 100),
                 0x5fa5d0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5fa5d4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x5fa5e0: (17156824, 'OBJC_IVAR_$_InteractionObject.flipped', 69),
        },
        classes={
                 0x5fa5a8: (15252588, 'OBJC_CLASS_$_Sign'),
        },
        instructions=[(6267320, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6268388, 'adceq r5, r6, r4, lsr 18')],
        calls=[(6267612, 'bl loc.imp.objc_msgSendSuper2'), (6267692, 'bl loc.imp.objc_msgSend'), (6267708, 'bl loc.imp.objc_msgSend'), (6267824, 'bl sym.signConnectionTypeAndOffsetForPos_intpair__int__World__int_'), (6267964, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6268136, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6268304, 'blx r2')],
        branches=[(6267640, 'bne', 6267656), (6267652, 'b', 6268316), (6267884, 'bne', 6268024), (6267984, 'beq', 6268020), (6268000, 'bne', 6268016), (6268016, 'b', 6268020), (6268020, 'b', 6268200), (6268056, 'bne', 6268196), (6268156, 'beq', 6268192), (6268172, 'bne', 6268188), (6268188, 'b', 6268192), (6268192, 'b', 6268196), (6268196, 'b', 6268200)],
        semantics=('[Sign -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]] (imp 0x005fa1b8, 268w): -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:] (0x5fa1b8, 268w, 13br, 7c): 9-arg placement ctor; `self=[super ...same 9 args]` (full pass-through, atPosition as 2 words); nil -> return nil. `self.text@100 = [[saveDict objectForKey:@"text" (@0xF7E388)] retain]`; `self.connectionType@112 = signConnectionTypeAndOffsetForPos(self.pos@16, &self.offsetType@116, self.world@4, 0)` (C fn @0x5f85a0; returns connection type, writes offsetType; 5th arg stack = 0); `if (self.offsetType==1) { t=tileAt(pos.x+1,pos.y); if(t && !t[0xb]) t[0xb]=0x30 } else if (==2) { same pos.x-1 }` (marker only, no worldContentsChanged); `self.flipped@69 = (self.offsetType==2)` (overrides the flipped arg); `[self initSubDerivedItems]`; return self..\n'),
    ),
    dict(
        name='sg_13',
        method='Sign -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=6269084,
        end=6270580,
        disasm='disasm_worldtileloader_sg_13.txt',
        base_add=6269100,
        base_literal=6270576,
        boundary='ARM.exidx end 0x005fae74 (listing bound); next ObjC IMP 0x005fae98 Sign -[isSignSubclass]',
        selectors={
                 0x5fae10: (15199128, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x5fae1c: (15199148, 'isSignSubclass'),
                 0x5fae20: (15199116, 'initSubDerivedItems'),
                 0x5fae28: (15199112, 'retain'),
                 0x5fae30: (15199108, 'objectForKey:'),
                 0x5fae44: (15199144, 'gzipInflate'),
                 0x5fae48: (15199132, 'getBytes:length:'),
                 0x5fae58: (15199136, 'length'),
                 0x5fae5c: (15199140, 'subdataWithRange:'),
                 0x5fae60: (15199156, 'countByEnumeratingWithState:objects:count:'),
                 0x5fae64: (15199152, 'blockheads'),
                 0x5fae6c: (15199160, 'netInteractionObjectWasLoaded:'),
        },
        imports={
                 0x5fae0c: (17151900, 'objc_msgSendSuper2'),
                 0x5fae18: (17151904, 'objc_msgSend'),
                 0x5fae2c: (16245704, '__CFConstantStringClassReference'),
                 0x5fae38: (16245688, '__CFConstantStringClassReference'),
                 0x5fae40: (16245640, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5fae24: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0x5fae34: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x5fae3c: (17156836, 'OBJC_IVAR_$_Sign.text', 100),
                 0x5fae50: (17156852, 'OBJC_IVAR_$_Sign.connectionType', 112),
                 0x5fae54: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
                 0x5fae68: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x5fae14: (15252588, 'OBJC_CLASS_$_Sign'),
        },
        instructions=[(6269084, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6270576, 'adceq r5, r6, r0, asr 4')],
        calls=[(6269236, 'blx r6'), (6269356, 'bl loc.imp.objc_msgSend'), (6269428, 'bl loc.imp.objc_msgSend'), (6269496, 'bl loc.imp.objc_msgSend'), (6269520, 'blx r2'), (6269524, 'bl 0x5fae74'), (6269744, 'blx r3'), (6269760, 'blx r2'), (6269804, 'blx r3'), (6269820, 'blx r2'), (6269864, 'blx r3'), (6269880, 'blx r2'), (6269920, 'blx r3'), (6269940, 'blx r2'), (6270072, 'blx r2'), (6270096, 'bl sym.imp.memset'), (6270144, 'blx lr'), (6270244, 'bl sym.imp.objc_enumerationMutation'), (6270324, 'blx ip'), (6270424, 'blx ip')],
        branches=[(6269264, 'bne', 6269280), (6269276, 'b', 6270464), (6269952, 'bne', 6270456), (6270156, 'beq', 6270448), (6270236, 'beq', 6270248), (6270352, 'blo', 6270200), (6270444, 'bne', 6270200), (6270448, 'b', 6270452), (6270452, 'b', 6270456)],
        semantics=('[Sign -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x005fa89c, 374w): -[initWithWorld:dynamicWorld:cache:netData:] (0x5fa89c, 374w, 9br, 20c): `self=[super ...same 4 args]`; nil -> nil. `[netData getBytes:buf length:0x30]` (buf @fp-0x78); `self.connectionType@112=buf[0x28]; self.offsetType@116=buf[0x29]`; `sub=[netData subdataWithRange:{0x30, [netData length]-0x30}]`; `dict=plistFromData([sub gzipInflate])` (local helper @0x5fae74 -> 0x601824: propertyListWithData:options:format:error: in @try/@catch + NSLog); `self.text@100=[dict[@"text"] retain]; self.ownerID@36=[dict[@"ownerID"] retain]; self.ownerName@84=[dict[@"ownerName"] retain]` (CFSTRs @0xF7E388/3B8/3C8); `[self initSubDerivedItems]`; `if (![self isSignSubclass]) { for (b in [self.dynamicWorld blockheads]) [b netInteractionObjectWasLoaded:self]; }` (NSFastEnumeration: state @fp-0xb8 (0x20 memset), objects buf sp+0xc0, count 0x10, objc_enumerationMutation guard). return self..\n'),
    ),
    dict(
        name='sg_14',
        method='Sign -[interactionObjectType]',
        types='S8@0:4',
        start=6268392,
        end=6268420,
        disasm='disasm_worldtileloader_sg_14.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005fa604 (listing bound); next ObjC IMP 0x005fa604 Sign -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6268392, 'sub sp, sp, 8'), (6268416, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Sign -[interactionObjectType]] (imp 0x005fa5e8, 7w): -[interactionObjectType] (0x5fa5e8, 7w): `return 4` (u16) - Sign\'s type id (base InteractionObject = 0)..\n'),
    ),
    dict(
        name='sg_15',
        method='Sign -[interactionRenderItemType]',
        types='i8@0:4',
        start=6295812,
        end=6295840,
        disasm='disasm_worldtileloader_sg_15.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00601120 (listing bound); next ObjC IMP 0x00601120 Sign -[paint:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6295812, 'sub sp, sp, 8'), (6295836, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Sign -[interactionRenderItemType]] (imp 0x00601104, 7w): -[interactionRenderItemType] (0x601104, 7w): `return 0xa3` (163)..\n'),
    ),
    dict(
        name='sg_16',
        method='Sign -[isPaintable]',
        types='c8@0:4',
        start=6296164,
        end=6296192,
        disasm='disasm_worldtileloader_sg_16.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00601314; body trimmed at the next IMP 0x00601280 Sign -[occupiesForegroundContents]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6296164, 'sub sp, sp, 8'), (6296188, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Sign -[isPaintable]] (imp 0x00601264, 7w): -[isPaintable] (0x601264, 7w): `return YES` (sxtb) - overrides base NO..\n'),
    ),
    dict(
        name='sg_17',
        method='Sign -[isSignSubclass]',
        types='c8@0:4',
        start=6270616,
        end=6270644,
        disasm='disasm_worldtileloader_sg_17.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005faeb4 (listing bound); next ObjC IMP 0x005faeb4 Sign -[getSaveDict]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6270616, 'sub sp, sp, 8'), (6270640, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Sign -[isSignSubclass]] (imp 0x005fae98, 7w): -[isSignSubclass] (0x5fae98, 7w): `return NO` (sxtb)..\n'),
    ),
    dict(
        name='sg_18',
        method='Sign -[loadRemoteUpdateDataDict:]',
        types='v12@0:4@8',
        start=6276516,
        end=6276996,
        disasm='disasm_worldtileloader_sg_18.txt',
        base_add=6276532,
        base_literal=6276992,
        boundary='ARM.exidx end 0x005fc784 (listing bound); next ObjC IMP 0x005fc784 Sign -[remoteUpdate:]',
        selectors={
                 0x5fc760: (15199112, 'retain'),
                 0x5fc768: (15199108, 'objectForKey:'),
                 0x5fc76c: (15199204, 'release'),
                 0x5fc778: (15199248, 'setText:'),
        },
        imports={
                 0x5fc75c: (17151904, 'objc_msgSend'),
                 0x5fc764: (16245704, '__CFConstantStringClassReference'),
                 0x5fc774: (16245688, '__CFConstantStringClassReference'),
                 0x5fc77c: (16245640, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5fc758: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0x5fc770: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={},
        instructions=[(6276516, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6276992, 'adceq r3, r6, r8, lsr r5')],
        calls=[(6276720, 'blx r7'), (6276748, 'blx r3'), (6276784, 'blx r3'), (6276808, 'blx r3'), (6276824, 'blx r2'), (6276880, 'blx ip'), (6276904, 'blx r3'), (6276920, 'blx r2')],
        branches=[],
        semantics=('[Sign -[loadRemoteUpdateDataDict:]] (imp 0x005fc5a4, 120w): -[loadRemoteUpdateDataDict:] (0x5fc5a4, 120w, 8c): `[self setText:[dict objectForKey:@"text" (@0xF7E388)]]; [self.ownerName@84 release]; self.ownerName=[[dict objectForKey:@"ownerName" (@0xF7E3C8)] retain]; [self.ownerID@36 release]; self.ownerID=[[dict objectForKey:@"ownerID" (@0xF7E3B8)] retain];`. No super call; apply order text, ownerName, ownerID..\n'),
    ),
    dict(
        name='sg_19',
        method='Sign -[netDataExtraDataDict]',
        types='@8@0:4',
        start=6271592,
        end=6272116,
        disasm='disasm_worldtileloader_sg_19.txt',
        base_add=6271608,
        base_literal=6272112,
        boundary='ARM.exidx end 0x005fb474 (listing bound); next ObjC IMP 0x005fb474 Sign -[creationNetDataForClient:]',
        selectors={
                 0x5fb450: (15199180, 'dictionary'),
                 0x5fb45c: (15199168, 'setObject:forKey:'),
        },
        imports={
                 0x5fb44c: (17151904, 'objc_msgSend'),
                 0x5fb458: (16245640, '__CFConstantStringClassReference'),
                 0x5fb464: (16245688, '__CFConstantStringClassReference'),
                 0x5fb46c: (16245704, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5fb448: (17156836, 'OBJC_IVAR_$_Sign.text', 100),
                 0x5fb460: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x5fb468: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
        },
        classes={
                 0x5fb454: (15245660, 'OBJC_CLASS_$_NSMutableDictionary'),
        },
        instructions=[(6271592, 'push {r4, r5, fp, lr}'), (6272112, 'adceq r4, r6, r4, ror r8')],
        calls=[(6271676, 'blx lr'), (6271800, 'blx ip'), (6271928, 'blx ip'), (6272056, 'blx ip')],
        branches=[(6271712, 'beq', 6271804), (6271840, 'beq', 6271932), (6271968, 'beq', 6272060)],
        semantics=('[Sign -[netDataExtraDataDict]] (imp 0x005fb268, 131w): -[netDataExtraDataDict] (0x5fb268, 131w, 3br, 4c): `dict=[NSMutableDictionary dictionary]; if(self.text@100) [dict setObject:self.text forKey:@"text"]; if(self.ownerID@36) [dict setObject:self.ownerID forKey:@"ownerID"]; if(self.ownerName@84) [dict setObject:self.ownerName forKey:@"ownerName"]; return dict;` (key CFSTRs @0xF7E388/3B8/3C8)..\n'),
    ),
    dict(
        name='sg_20',
        method='Sign -[occupiesForegroundContents]',
        types='c8@0:4',
        start=6296192,
        end=6296220,
        disasm='disasm_worldtileloader_sg_20.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00601314; body trimmed at the next IMP 0x0060129c Sign -[offsetType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6296192, 'sub sp, sp, 8'), (6296216, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Sign -[occupiesForegroundContents]] (imp 0x00601280, 7w): -[occupiesForegroundContents] (0x601280, 7w): `return YES` (sxtb)..\n'),
    ),
    dict(
        name='sg_21',
        method='Sign -[offsetType]',
        types='i8@0:4',
        start=6296220,
        end=6296280,
        disasm='disasm_worldtileloader_sg_21.txt',
        base_add=6296244,
        base_literal=6296276,
        boundary='ARM.exidx end 0x00601314; body trimmed at the next IMP 0x006012d8 Sign -[connectionType]',
        selectors={},
        imports={},
        ivars={
                 0x6012d0: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
        },
        classes={},
        instructions=[(6296220, 'sub sp, sp, 8'), (6296276, 'adceq lr, r5, r8, lsr r8')],
        calls=[],
        branches=[],
        semantics=('[Sign -[offsetType]] (imp 0x0060129c, 15w): -[offsetType] (0x60129c, 15w): plain ivar getter `return self.offsetType@116` (int)..\n'),
    ),
    dict(
        name='sg_22',
        method='Sign -[paint:]',
        types='v12@0:4S8',
        start=6295840,
        end=6296164,
        disasm='disasm_worldtileloader_sg_22.txt',
        base_add=6295856,
        base_literal=6296160,
        boundary='ARM.exidx end 0x00601264 (listing bound); next ObjC IMP 0x00601264 Sign -[isPaintable]',
        selectors={
                 0x601240: (15199096, 'updateBitmapString'),
                 0x601258: (15199240, 'objectType'),
                 0x60125c: (15199244, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x60123c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x601238: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x601244: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x601248: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x601250: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x601254: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(6295840, 'push {r4, r5, fp, lr}'), (6296160, 'invalid')],
        calls=[(6295936, 'blx lr'), (6296072, 'bl loc.imp.objc_msgSend'), (6296108, 'bl loc.imp.objc_msgSend')],
        branches=[(6295964, 'bne', 6296112)],
        semantics=('[Sign -[paint:]] (imp 0x00601120, 81w): -[paint:] (0x601120, 81w, 1br, 3c): `self.paintColor@88 = (u16)color; [self updateBitmapString]; if (!self.isNet@52) { self.updateNeedsToBeSent@49 = YES; [[self.dynamicWorld@8] dynamicWorldChangedAtPos:self.pos@16 objectType:[self objectType]]; }` (pos {x,y} passed in 2 registers + type as stack arg)..\n'),
    ),
    dict(
        name='sg_23',
        method='Sign -[remoteUpdate:]',
        types='v12@0:4@8',
        start=6276996,
        end=6277656,
        disasm='disasm_worldtileloader_sg_23.txt',
        base_add=6277012,
        base_literal=6277652,
        boundary='ARM.exidx end 0x005fca18 (listing bound); next ObjC IMP 0x005fca18 Sign -[update:accurateDT:isSimulation:]',
        selectors={
                 0x5fc9dc: (15199252, 'remoteUpdate:'),
                 0x5fc9f0: (15199256, 'loadRemoteUpdateDataDict:'),
                 0x5fc9f4: (15199144, 'gzipInflate'),
                 0x5fc9f8: (15199136, 'length'),
                 0x5fca00: (15199140, 'subdataWithRange:'),
                 0x5fca0c: (15199132, 'getBytes:length:'),
                 0x5fca10: (15199096, 'updateBitmapString'),
        },
        imports={
                 0x5fc9d8: (17151900, 'objc_msgSendSuper2'),
                 0x5fc9ec: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5fc9e4: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x5fc9e8: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5fca04: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
                 0x5fca08: (17156852, 'OBJC_IVAR_$_Sign.connectionType', 112),
        },
        classes={
                 0x5fc9e0: (15252588, 'OBJC_CLASS_$_Sign'),
        },
        instructions=[(6276996, 'push {r4, r5, r6, sl, fp, lr}'), (6277652, 'adceq r3, r6, r8, asr r3')],
        calls=[(6277116, 'blx lr'), (6277220, 'bl loc.imp.objc_msgSend'), (6277288, 'bl loc.imp.objc_msgSend'), (6277312, 'blx r2'), (6277316, 'bl 0x5fae74'), (6277368, 'blx r3'), (6277456, 'blx lr'), (6277580, 'blx r2')],
        branches=[(6277156, 'bne', 6277372), (6277536, 'beq', 6277584)],
        semantics=('[Sign -[remoteUpdate:]] (imp 0x005fc784, 165w): -[remoteUpdate:] (0x5fc784, 165w, 2br, 8c): saves old self.paintColor@88 (ldrh); `[super remoteUpdate:data]` (objc_msgSendSuper2); `if (self.currentBlockhead@56 == nil) { sub=[data subdataWithRange:{0x30, [data length]-0x30}]; dict=plistFromData([sub gzipInflate]) (@0x5fae74); [self loadRemoteUpdateDataDict:dict]; }`; then unconditionally: `[data getBytes:buf length:0x30]; self.connectionType@112=buf[0x28]; self.offsetType@116=buf[0x29]; if (oldPaintColor != self.paintColor) [self updateBitmapString];`..\n'),
    ),
    dict(
        name='sg_24',
        method='Sign -[remove:]',
        types='v12@0:4@8',
        start=6292856,
        end=6294344,
        disasm='disasm_worldtileloader_sg_24.txt',
        base_add=6292872,
        base_literal=6294340,
        boundary='ARM.exidx end 0x00600b48 (listing bound); next ObjC IMP 0x00600b48 Sign -[destroyItemType]',
        selectors={
                 0x600af8: (15199312, 'isNet'),
                 0x600b08: (15199316, 'stopInteracting'),
                 0x600b20: (15199100, 'worldContentsChangedAtPos:'),
                 0x600b28: (15199328, 'setNeedsRemoved:'),
                 0x600b2c: (15199324, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:'),
                 0x600b34: (15199308, 'destroyItemType'),
                 0x600b38: (15199164, 'getSaveDict'),
                 0x600b3c: (15199320, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x600af4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x600ae8: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x600aec: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x600af0: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x600afc: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x600b00: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
                 0x600b0c: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
                 0x600b10: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x600b14: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x600b18: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x600b40: (17156820, 'OBJC_IVAR_$_InteractionObject.needsToBeRemovedWhenInteractionEnds', 96),
        },
        classes={},
        instructions=[(6292856, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6294340, 'adceq pc, r5, r4, ror 10')],
        calls=[(6293060, 'blx r2'), (6293220, 'blx r2'), (6293340, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6293476, 'bl sym.makeIntpair_int__int_'), (6293504, 'bl loc.imp.objc_msgSend'), (6293624, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6293760, 'bl sym.makeIntpair_int__int_'), (6293788, 'bl loc.imp.objc_msgSend'), (6293972, 'bl loc.imp.objc_msgSend'), (6294004, 'bl loc.imp.objc_msgSend'), (6294092, 'bl loc.imp.objc_msgSend'), (6294208, 'blx r6'), (6294236, 'blx r3')],
        branches=[(6292920, 'bne', 6292960), (6292956, 'beq', 6292964), (6292960, 'b', 6294240), (6292996, 'beq', 6293228), (6293072, 'bne', 6293124), (6293116, 'beq', 6293160), (6293120, 'b', 6293124), (6293156, 'b', 6294240), (6293224, 'b', 6293228), (6293260, 'bne', 6293512), (6293360, 'beq', 6293392), (6293376, 'bne', 6293392), (6293508, 'b', 6293796), (6293544, 'bne', 6293792), (6293644, 'beq', 6293676), (6293660, 'bne', 6293676), (6293792, 'b', 6293796)],
        semantics=('[Sign -[remove:]] (imp 0x00600578, 372w): -[remove:] (0x600578, 372w, 17br, 13c): guards `if (self.needsRemoved@48) return; if (self.isNet@52) return;`; `if (self.isInUse@68) { if ([self.currentBlockhead@56 isNet]) { self.needsToBeRemovedWhenInteractionEnds@96=1; return; } if (self.remoteBlockheadInUseUniqueID@72 != 0) { ...=1; return; } [self.currentBlockhead stopInteracting]; }`; old-side tile cleanup (offsetType==1 -> pos.x+1; ==2 -> pos.x-1: if(t && t[0xb]==0x30) t[0xb]=0; [dynWorld worldContentsChangedAtPos:...]); real tail: `[[self.dynamicWorld] createFreeBlockAtPosition:self.pos ofType:[self destroyItemType] dataA:0 dataB:0 subItems:0 dynamicObjectSaveDict:[self getSaveDict] hovers:0 playSound:1 priorityBlockhead:arg]`; `[self.world removeTileAtWorldX:pos.x worldY:pos.y createContentsFreeblockCount:0 createForegroundContentsFreeblockCount:0 removeBlockhead:arg onlyRemoveCOntents:0 onlyRemoveForegroundContents:1]`; `[self setNeedsRemoved:1]`. remove: arg (@) is handed through as priorityBlockhead/removeBlockhead. NOT a stub (contrast E146 base stub)..\n'),
    ),
    dict(
        name='sg_25',
        method='Sign -[removeFromMacroBlock]',
        types='v8@0:4',
        start=6273260,
        end=6273368,
        disasm='disasm_worldtileloader_sg_25.txt',
        base_add=6273276,
        base_literal=6273364,
        boundary='ARM.exidx end 0x005fb958 (listing bound); next ObjC IMP 0x005fb958 Sign -[updateBitmapString]',
        selectors={
                 0x5fb94c: (15199212, 'removeFromMacroBlock'),
        },
        imports={
                 0x5fb948: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0x5fb950: (15252588, 'OBJC_CLASS_$_Sign'),
        },
        instructions=[(6273260, 'push {r4, sl, fp, lr}'), (6273364, 'invalid')],
        calls=[(6273340, 'blx ip')],
        branches=[],
        semantics=('[Sign -[removeFromMacroBlock]] (imp 0x005fb8ec, 27w): -[removeFromMacroBlock] (0x5fb8ec, 27w, 1c): pure `[super removeFromMacroBlock]` via objc_msgSendSuper2(&super{self, Sign}) - InteractionObject\'s implementation owns the work..\n'),
    ),
    dict(
        name='sg_26',
        method='Sign -[requiresHumanInteraction]',
        types='c8@0:4',
        start=6294468,
        end=6294496,
        disasm='disasm_worldtileloader_sg_26.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00600be0 (listing bound); next ObjC IMP 0x00600be0 Sign -[setNeedsRemoved:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6294468, 'sub sp, sp, 8'), (6294492, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Sign -[requiresHumanInteraction]] (imp 0x00600bc4, 7w): -[requiresHumanInteraction] (0x600bc4, 7w): `return YES` (sxtb)..\n'),
    ),
    dict(
        name='sg_27',
        method='Sign -[requiresSingleLineTextEditing]',
        types='c8@0:4',
        start=6295304,
        end=6295332,
        disasm='disasm_worldtileloader_sg_27.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00600f24 (listing bound); next ObjC IMP 0x00600f24 Sign -[canBeUsedByBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6295304, 'sub sp, sp, 8'), (6295328, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Sign -[requiresSingleLineTextEditing]] (imp 0x00600f08, 7w): -[requiresSingleLineTextEditing] (0x600f08, 7w): `return NO` (sxtb)..\n'),
    ),
    dict(
        name='sg_28',
        method='Sign -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=6294496,
        end=6295224,
        disasm='disasm_worldtileloader_sg_28.txt',
        base_add=6294512,
        base_literal=6295220,
        boundary='ARM.exidx end 0x00600eb8 (listing bound); next ObjC IMP 0x00600eb8 Sign -[twoBlocksWide]',
        selectors={
                 0x600ea0: (15199100, 'worldContentsChangedAtPos:'),
                 0x600eac: (15199328, 'setNeedsRemoved:'),
        },
        imports={
                 0x600ea8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x600e8c: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
                 0x600e90: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x600e94: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x600e98: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x600eb0: (15252588, 'OBJC_CLASS_$_Sign'),
        },
        instructions=[(6294496, 'push {r4, sl, fp, lr}'), (6295220, 'invalid')],
        calls=[(6294640, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6294776, 'bl sym.makeIntpair_int__int_'), (6294804, 'bl loc.imp.objc_msgSend'), (6294924, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6295060, 'bl sym.makeIntpair_int__int_'), (6295088, 'bl loc.imp.objc_msgSend'), (6295168, 'blx r3')],
        branches=[(6294560, 'bne', 6294812), (6294660, 'beq', 6294692), (6294676, 'bne', 6294692), (6294808, 'b', 6295096), (6294844, 'bne', 6295092), (6294944, 'beq', 6294976), (6294960, 'bne', 6294976), (6295092, 'b', 6295096)],
        semantics=('[Sign -[setNeedsRemoved:]] (imp 0x00600be0, 182w): -[setNeedsRemoved:] (0x600be0, 182w, 8br, 7c): `if (self.offsetType@116==1) { t=[self.world tileAtWorldPositionLoaded:self.pos.x+1, pos.y]; if(t && t[0xb]==0x30) t[0xb]=0; [[self.dynamicWorld@8] worldContentsChangedAtPos:makeIntpair(pos.x+1,pos.y)]; } else if (self.offsetType==2) { same pos.x-1 }`; then `[super setNeedsRemoved:flag]` (objc_msgSendSuper2; char arg sxtb). Pairs with sg_12/sg_11 (0x30 marker set at placement, cleared here)..\n'),
    ),
    dict(
        name='sg_29',
        method='Sign -[setText:]',
        types='v12@0:4@8',
        start=6276072,
        end=6276456,
        disasm='disasm_worldtileloader_sg_29.txt',
        base_add=6276088,
        base_literal=6276452,
        boundary='ARM.exidx end 0x005fc568 (listing bound); next ObjC IMP 0x005fc568 Sign -[text]',
        selectors={
                 0x5fc53c: (15199232, 'isEqualToString:'),
                 0x5fc548: (15199236, 'autorelease'),
                 0x5fc54c: (15199112, 'retain'),
                 0x5fc550: (15199096, 'updateBitmapString'),
                 0x5fc55c: (15199240, 'objectType'),
                 0x5fc560: (15199244, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x5fc538: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5fc540: (17156836, 'OBJC_IVAR_$_Sign.text', 100),
                 0x5fc554: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5fc558: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(6276072, 'push {r4, sl, fp, lr}'), (6276452, 'invalid')],
        calls=[(6276152, 'blx ip'), (6276216, 'bl loc.imp.objc_msgSend'), (6276248, 'bl loc.imp.objc_msgSend'), (6276284, 'bl loc.imp.objc_msgSend'), (6276360, 'bl loc.imp.objc_msgSend'), (6276396, 'bl loc.imp.objc_msgSend')],
        branches=[(6276164, 'bne', 6276400)],
        semantics=('[Sign -[setText:]] (imp 0x005fc3e8, 96w): -[setText:] (0x5fc3e8, 96w, 1br, 6c): `if ([text isEqualToString:self.text@100]) return; [self.text autorelease]; self.text=[text retain]; [self updateBitmapString]; [[self.dynamicWorld@8] dynamicWorldChangedAtPos:self.pos@16 objectType:[self objectType]];`. No isNet gate and no updateNeedsToBeSent here (unlike paint:)..\n'),
    ),
    dict(
        name='sg_30',
        method='Sign -[text]',
        types='@8@0:4',
        start=6276456,
        end=6276516,
        disasm='disasm_worldtileloader_sg_30.txt',
        base_add=6276464,
        base_literal=6276512,
        boundary='ARM.exidx end 0x005fc5a4 (listing bound); next ObjC IMP 0x005fc5a4 Sign -[loadRemoteUpdateDataDict:]',
        selectors={},
        imports={},
        ivars={
                 0x5fc59c: (17156836, 'OBJC_IVAR_$_Sign.text', 100),
        },
        classes={},
        instructions=[(6276456, 'sub sp, sp, 8'), (6276512, 'adceq r3, r6, ip, ror r5')],
        calls=[],
        branches=[],
        semantics=('[Sign -[text]] (imp 0x005fc568, 15w): -[text] (0x5fc568, 15w): plain ivar getter `return self.text@100` (no dmb; direct ldr r0,[r0,r1])..\n'),
    ),
    dict(
        name='sg_31',
        method='Sign -[title]',
        types='@8@0:4',
        start=6294372,
        end=6294420,
        disasm='disasm_worldtileloader_sg_31.txt',
        base_add=6294380,
        base_literal=6294416,
        boundary='ARM.exidx end 0x00600be0; body trimmed at the next IMP 0x00600b94 Sign -[actionTitle]',
        selectors={},
        imports={
                 0x600b8c: (16245720, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(6294372, 'sub sp, sp, 8'), (6294416, 'adceq lr, r5, r0, lsl 31')],
        calls=[],
        branches=[],
        semantics=('[Sign -[title]] (imp 0x00600b64, 12w): -[title] (0x600b64, 12w, trimmed): returns the static CFString "SIGN" @0xF7E3D8 (flags 0x7c8, len 4). Base InteractionObject title = @""..\n'),
    ),
    dict(
        name='sg_32',
        method='Sign -[twoBlocksWide]',
        types='c8@0:4',
        start=6295224,
        end=6295304,
        disasm='disasm_worldtileloader_sg_32.txt',
        base_add=6295232,
        base_literal=6295300,
        boundary='ARM.exidx end 0x00600f24; body trimmed at the next IMP 0x00600f08 Sign -[requiresSingleLineTextEditing]',
        selectors={},
        imports={},
        ivars={
                 0x600f00: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
        },
        classes={},
        instructions=[(6295224, 'sub sp, sp, 8'), (6295300, 'adceq lr, r5, ip, lsr 24')],
        calls=[],
        branches=[],
        semantics=('[Sign -[twoBlocksWide]] (imp 0x00600eb8, 20w): -[twoBlocksWide] (0x600eb8, 20w): `return self.offsetType@116 != 0` (cmp/movne/and 1/sxtb)..\n'),
    ),
    dict(
        name='sg_33',
        method='Sign -[updateBitmapString]',
        types='v8@0:4',
        start=6273368,
        end=6274404,
        disasm='disasm_worldtileloader_sg_33.txt',
        base_add=6273384,
        base_literal=6274400,
        boundary='ARM.exidx end 0x005fbd64 (listing bound); next ObjC IMP 0x005fc3e8 Sign -[setText:]',
        selectors={
                 0x5fbd34: (15199204, 'release'),
                 0x5fbd40: (15199216, 'alloc'),
                 0x5fbd48: (15199224, 'embossedFont'),
                 0x5fbd50: (15199220, 'blackFont'),
                 0x5fbd5c: (15199228, 'initWithString:dimensions:horizontalAlignment:font:cache:color:'),
        },
        imports={
                 0x5fbd30: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5fbd28: (17156836, 'OBJC_IVAR_$_Sign.text', 100),
                 0x5fbd2c: (17156856, 'OBJC_IVAR_$_Sign.bitmapString', 104),
                 0x5fbd38: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x5fbd3c: (17156860, 'OBJC_IVAR_$_Sign.blackText', 120),
                 0x5fbd54: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
        },
        classes={
                 0x5fbd44: (15245668, 'OBJC_CLASS_$_BitmapString'),
                 0x5fbd4c: (15245672, 'OBJC_CLASS_$_BitmapFont'),
        },
        instructions=[(6273368, 'push {r4, r5, r6, r7, fp, lr}'), (6274400, 'adceq r4, r6, r4, lsl 3')],
        calls=[(6273468, 'blx r4'), (6273628, 'bl method.Vector.Vector_float__float__float__float_'), (6273680, 'bl 0x5fbd64'), (6273720, 'bl method.Vector.operator_float__'), (6273744, 'bl method.Vector.operator_float__'), (6273764, 'bl method.Vector.operator_float__'), (6273904, 'blx r2'), (6273968, 'bl 0x5fc370'), (6274056, 'blx r2'), (6274116, 'blx r2'), (6274216, 'bl 0x5fc39c'), (6274312, 'bl loc.imp.objc_msgSend')],
        branches=[(6273520, 'beq', 6274336), (6273584, 'beq', 6273852), (6273812, 'ble', 6273848), (6273848, 'b', 6273852), (6274004, 'beq', 6274068), (6274064, 'b', 6274124)],
        semantics=('[Sign -[updateBitmapString]] (imp 0x005fb958, 259w): -[updateBitmapString] (0x5fb958, 259w, 6br, 12c): `if (self.bitmapString@104) { [self.bitmapString release]; self.bitmapString=nil; } if (self.text@100==nil) return; self.blackText@120=NO; if (self.paintColor@88 != 0) { Vector c = colorFromPacked16(self.paintColor, 0) (helper @0x5fbd64: u16 nibbles -> RGBA floats; mode 0x116 -> white); if (c[1] > 0.75 - (c[0]+c[2])*0.25) self.blackText=YES; } self.bitmapString = [[BitmapString alloc] initWithString:self.text dimensions:{130.0f,48.0f} (helper @0x5fc370) horizontalAlignment:1 font:(blackText ? [BitmapFont blackFont] : [BitmapFont embossedFont]) cache:self.cache@32 color:(1,1,1,1) (helper @0x5fc39c)];`..\n'),
    ),
    dict(
        name='sg_34',
        method='Sign -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=6271508,
        end=6271592,
        disasm='disasm_worldtileloader_sg_34.txt',
        base_add=6271524,
        base_literal=6271588,
        boundary='ARM.exidx end 0x005fb268 (listing bound); next ObjC IMP 0x005fb268 Sign -[netDataExtraDataDict]',
        selectors={
                 0x5fb260: (15199176, 'creationNetDataForClient:'),
        },
        imports={
                 0x5fb25c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6271508, 'push {fp, lr}'), (6271588, 'adceq r4, r6, r8, asr 17')],
        calls=[(6271568, 'blx ip')],
        branches=[],
        semantics=('[Sign -[updateNetDataForClient:]] (imp 0x005fb214, 21w): -[updateNetDataForClient:] (0x5fb214, 21w, 1c): pure forward `return [self creationNetDataForClient:client]` (client passed through unchanged)..\n'),
    ),
    dict(
        name='sg_35',
        method='Sign -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=6290264,
        end=6292648,
        disasm='disasm_worldtileloader_sg_35.txt',
        base_add=6290280,
        base_literal=6292644,
        boundary='ARM.exidx end 0x006004a8 (listing bound); next ObjC IMP 0x006004a8 Sign -[freeblockCreationItemType]',
        selectors={
                 0x600478: (15199100, 'worldContentsChangedAtPos:'),
                 0x600494: (15199240, 'objectType'),
                 0x600498: (15199244, 'dynamicWorldChangedAtPos:objectType:'),
                 0x6004a0: (15199304, 'remove:'),
        },
        imports={
                 0x60049c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x600458: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x60045c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x600460: (17156852, 'OBJC_IVAR_$_Sign.connectionType', 112),
                 0x600464: (17156848, 'OBJC_IVAR_$_Sign.offsetType', 116),
                 0x60046c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x600470: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x60048c: (17156824, 'OBJC_IVAR_$_InteractionObject.flipped', 69),
                 0x600490: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(6290264, 'push {r4, r5, fp, lr}'), (6292644, 'adceq pc, r5, r4, lsl 31')],
        calls=[(6290920, 'bl sym.signConnectionTypeAndOffsetForPos_intpair__int__World__int_'), (6291120, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6291256, 'bl sym.makeIntpair_int__int_'), (6291284, 'bl loc.imp.objc_msgSend'), (6291404, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6291540, 'bl sym.makeIntpair_int__int_'), (6291568, 'bl loc.imp.objc_msgSend'), (6291732, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6291868, 'bl sym.makeIntpair_int__int_'), (6291896, 'bl loc.imp.objc_msgSend'), (6292016, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6292152, 'bl sym.makeIntpair_int__int_'), (6292180, 'bl loc.imp.objc_msgSend'), (6292368, 'bl loc.imp.objc_msgSend'), (6292404, 'bl loc.imp.objc_msgSend'), (6292488, 'blx r3')],
        branches=[(6290328, 'beq', 6290336), (6290332, 'b', 6292560), (6290572, 'beq', 6292560), (6290648, 'bgt', 6292496), (6290692, 'blt', 6292496), (6290736, 'bgt', 6292496), (6290780, 'blt', 6292496), (6290964, 'bne', 6291008), (6291004, 'beq', 6292408), (6291040, 'bne', 6291292), (6291140, 'beq', 6291172), (6291156, 'bne', 6291172), (6291288, 'b', 6291576), (6291324, 'bne', 6291572), (6291424, 'beq', 6291456), (6291440, 'bne', 6291456), (6291572, 'b', 6291576), (6291616, 'beq', 6292192), (6291652, 'bne', 6291904), (6291752, 'beq', 6291784), (6291768, 'bne', 6291784), (6291900, 'b', 6292188), (6291936, 'bne', 6292184), (6292036, 'beq', 6292068), (6292052, 'bne', 6292068), (6292184, 'b', 6292188), (6292188, 'b', 6292192), (6292440, 'bne', 6292492), (6292492, 'b', 6292496), (6292496, 'b', 6292500), (6292556, 'b', 6290420)],
        semantics=('[Sign -[worldChanged:]] (imp 0x005ffb58, 596w): -[worldChanged:] (0x5ffb58, 596w, 31br, 16c): arg = std::vector<intpair>* (tsv ^{vector<intpair,...>}). `if (self.isNet@52) return;` then `for (it=vec->begin(); it!=vec->end(); ++it)` (+8 bytes/item): `if (ch.x>pos.x+1) continue; if (ch.x<pos.x-1) continue; if (ch.y>pos.y+1) continue; if (ch.y<pos.y-1) continue;` `int newOffset=self.offsetType@116; int newConn=signConnectionTypeAndOffsetForPos(self.pos,&newOffset,self.world@4,self.connectionType@112)` (stack arg = current conn); `if (newConn!=self.connectionType || newOffset!=self.offsetType) { old-side cleanup (offsetType==1->pos.x+1 clear t[0xb]==0x30; ==2->pos.x-1; each + [dynWorld worldContentsChangedAtPos:makeIntpair(...)]); self.offsetType=newOffset; if (newConn!=0) { new-side set (offsetType==1->pos.x+1: if(t && !t[0xb]) t[0xb]=0x30; ==2->pos.x-1; each + worldContentsChanged) } self.flipped@69=(offsetType==2); self.connectionType@112=newConn; self.updateNeedsToBeSent@49=1; [[self.dynamicWorld] dynamicWorldChangedAtPos:self.pos objectType:[self objectType]]; } if (self.connectionType==0) [self remove:0];` - re-derives wall connectivity when any change lands in the 3x3 neighborhood; removes the sign if it ends up unconnected. Constants: sub sp,#328 (GL e24ddf52); no VFP..\n'),
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
        'batch': 'Sign (E147): the signpost interaction object; 36 bodies',
        'claim': ('the signpost object (text bitmap render, connection-type switching, recompute)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'sign.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale sign.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
