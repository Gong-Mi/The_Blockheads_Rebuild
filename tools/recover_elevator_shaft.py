#!/usr/bin/env python3
"""Hash-gated recovery of the ElevatorShaft closure.

26 bodies, 4175 instruction words total, from the pinned original libApplication.so (1.7.6, armeabi-v7a):
init quartets (atPosition: 222w / saveDict: 214w / netData: 212w / getSaveDict 223w),\ncreationNet 209w, remoteUpdate 127w, updateNetDataForClient 21w, dealloc 49w,\ndraw 714w (door render), worldChanged 308w, staticGeometryDrawQuadCount 26w, addDrawQuadData 503w,\nstaticGeometryDrawCubeCount 23w, addDrawCubeData 802w, paint 134w, open 16w, removeFromMacroBlock 95w,\ninitSubDerivedItems 184w, lastKnownMotorPos 24w, objectType/isPaintable/occupiesNormalContents/freeblock quartet.\nEvery instruction word is re-verified; tool refuses to emit on drift.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
EXPECTED_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
EXPECTED_BASE = 0x0105FAF4

ROUTE_TARGETS = {
    'bl 0xcad974': 0X00CAD974,
    'bl 0xcae0ac': 0X00CAE0AC,
    'bl 0xcaf000': 0X00CAF000,
    'bl 0xcaf074': 0X00CAF074,
    'bl loc.imp.objc_msgSend': 0X001C281C,
    'bl loc.imp.objc_msgSendSuper2': 0X001C29FC,
    'bl loc.imp.objc_msgSend_stret': 0X001C2918,
    'bl method.Vector.Vector_float__float__float__float_': 0X004D0D08,
    'bl method.Vector2.operator_float__': 0X004BDAAC,
    'bl sym.fillQuadBufferColored_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__Vector__int__int_': 0X00D94C88,
    'bl sym.imp.memcpy': 0X001C2894,
    'bl sym.imp.memset': 0X001C2924,
    'bl sym.imp.objc_copyStruct': 0X001C2888,
    'bl sym.paintedIndexForImageIndex_int_': 0X00A15E28,
    'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_': 0X00A19670,
    'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_': 0X00A19598,
    'bl sym.texCoordsForImageIndex_int_': 0X004D6820,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0X00A12F24,
    'bl sym.tileIsSolid_Tile_': 0X00A1179C,
}

SPECS = [
    dict(
        name='s_subderived',
        method='ElevatorShaft -[initSubDerivedItems]',
        types='v8@0:4',
        start=13290584,
        end=13291320,
        disasm='disasm_elevatorshaft_initsubderiveditems.txt',
        base_add=13290600,
        base_literal=13291316,
        boundary='consecutive IMPs: [objectType] follows at 0x00cacf38',
        selectors={13291292: (15236048, 'macroTiles'), 13291304: (15236052, 'elevatorMotorForShaftAtPos:'), 13291308: (15236056, 'pos')},
        imports={},
        ivars={13291280: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13291288: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 13291296: (17167508, 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos', 60), 13291300: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 13291312: (17167512, 'OBJC_IVAR_$_ElevatorShaft.solidTile', 86)},
        classes={},
        instructions=[(13290584, 'push {r4, r5, fp, lr}'), (13290712, 'bl loc.imp.objc_msgSend'), (13291276, 'pop {r4, r5, fp, pc}')],
        semantics=('initSubDerivedItems: [self macroTiles]-style chain then reloadDrawBlockDynamicObjectStaticGeometryForTile + reloadDrawBlockDynamicObjectQuadsForTile; computes the motor position for the tile ([... sel 0xffe280e0] intpair result, stret 8-byte copy with memset fallback) and stores it into ElevatorShaft.lastKnownMotorPos@60; then tileIsSolid(tile) -> the solid byte@... written (0x9a4).'),
        calls=[(13290712, 'bl loc.imp.objc_msgSend'), (13290756, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (13290816, 'bl loc.imp.objc_msgSend'), (13290860, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (13290916, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13290996, 'bl loc.imp.objc_msgSend'), (13291096, 'bl loc.imp.objc_msgSend_stret'), (13291132, 'bl sym.imp.memset'), (13291228, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13291240, 'bl sym.tileIsSolid_Tile_')],
        branches=[(13291016, 'beq', 13291156), (13291080, 'beq', 13291104), (13291100, 'b', 13291136)],
    ),
    dict(
        name='s_objtype',
        method='ElevatorShaft -[objectType]',
        types='i8@0:4',
        start=13291320,
        end=13291348,
        disasm='disasm_elevatorshaft_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [initWithWorld:...atPosition:...] follows at 0x00cacf54',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13291320, 'sub sp, sp, 8'), (13291344, 'bx lr')],
        semantics=('objectType = 0x38 (56).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='s_initpos',
        method='ElevatorShaft -[initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:]',
        types='@40@0:4@8@12{?=ii}16@24i28@32@36',
        start=13291348,
        end=13292236,
        disasm='disasm_elevatorshaft_initwithworld_atposition.txt',
        base_add=13291364,
        base_literal=13292232,
        boundary='consecutive IMPs: [initWithWorld:...saveDict:...] follows at 0x00cad2cc',
        selectors={13292180: (15236060, 'initWithWorld:dynamicWorld:atPosition:cache:'), 13292196: (15236068, 'objectForKey:'), 13292204: (15236064, 'retain'), 13292208: (15236076, 'initSubDerivedItems'), 13292224: (15236072, 'unsignedIntValue')},
        imports={13292192: (17151904, 'objc_msgSend')},
        ivars={13292184: (17167516, 'OBJC_IVAR_$_ElevatorShaft.itemType', 56), 13292200: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 13292212: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13292216: (17167508, 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos', 60), 13292220: (17167520, 'OBJC_IVAR_$_ElevatorShaft.paintColor', 84)},
        classes={13292172: (15253224, 'OBJC_CLASS_$_ElevatorShaft')},
        instructions=[(13291348, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13291548, 'bl loc.imp.objc_msgSendSuper2'), (13292168, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Full placement: objc_msgSendSuper2 init + nil guard; stores the type arg via slot 0xfffff9a8 (u16 field); saveDict branch: [saveDict objectForKey:] + intValue or the f436b4-key conditional decode, store; tail: post-init chain (sel 0xffe280f4/0xffe280f8 pair) + copies self.pos intpair into lastKnownMotorPos@60; return self.'),
        calls=[(13291548, 'bl loc.imp.objc_msgSendSuper2'), (13291684, 'blx r2'), (13291772, 'blx r3'), (13291872, 'blx lr'), (13291888, 'blx r2'), (13292044, 'blx r7'), (13292060, 'blx r2'), (13292148, 'blx lr')],
        branches=[(13291576, 'bne', 13291592), (13291588, 'b', 13292160), (13291636, 'beq', 13291712), (13291708, 'b', 13291916), (13291784, 'beq', 13291912), (13291912, 'b', 13291916)],
    ),
    dict(
        name='s_initsave',
        method='ElevatorShaft -[initWithWorld:dynamicWorld:saveDict:cache:]',
        types='@24@0:4@8@12@16@20',
        start=13292236,
        end=13293092,
        disasm='disasm_elevatorshaft_initwithworld_savedict_closure.txt',
        base_add=13292252,
        base_literal=13293088,
        boundary='consecutive IMPs: [initWithWorld:...netData:] follows at 0x00cad624',
        selectors={13293020: (15236080, 'initWithWorld:dynamicWorld:saveDict:cache:'), 13293032: (15236076, 'initSubDerivedItems'), 13293040: (15236072, 'unsignedIntValue'), 13293048: (15236068, 'objectForKey:'), 13293056: (15236064, 'retain'), 13293068: (15236084, 'intValue')},
        imports={13293016: (17151900, 'objc_msgSendSuper2'), 13293028: (17151904, 'objc_msgSend')},
        ivars={13293036: (17167520, 'OBJC_IVAR_$_ElevatorShaft.paintColor', 84), 13293052: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 13293064: (17167508, 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos', 60), 13293080: (17167516, 'OBJC_IVAR_$_ElevatorShaft.itemType', 56)},
        classes={13293024: (15253224, 'OBJC_CLASS_$_ElevatorShaft')},
        instructions=[(13292236, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13292388, 'blx r6'), (13293012, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Save-dict restore: objc_msgSendSuper2 init + nil guard; seven objectForKey:+intValue decodes written as str/str/strh/str pairs (u16 type field, lastKnownMotorPos pair, paint u16@9ac, etc; CFString keys 0xfff436c4/f4/e4/d4/b4 - the b2i key block); return self.'),
        calls=[(13292388, 'blx r6'), (13292696, 'blx r6'), (13292712, 'blx r2'), (13292756, 'blx r3'), (13292772, 'blx r2'), (13292816, 'blx r3'), (13292832, 'blx r2'), (13292876, 'blx r3'), (13292892, 'blx r2'), (13292936, 'blx r3'), (13292952, 'blx r2'), (13292992, 'blx r3')],
        branches=[(13292416, 'bne', 13292432), (13292428, 'b', 13293004)],
    ),
    dict(
        name='s_initnet',
        method='ElevatorShaft -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=13293092,
        end=13293940,
        disasm='disasm_elevatorshaft_initwithworld_netdata.txt',
        base_add=13293108,
        base_literal=13293936,
        boundary='ARM.exidx end 0x00cad974; 9-word tail gap before [getSaveDict] at 0x00cad998',
        selectors={13293872: (15236088, 'initWithWorld:dynamicWorld:cache:netData:'), 13293884: (15236096, 'length'), 13293900: (15236092, 'getBytes:length:'), 13293908: (15236064, 'retain'), 13293916: (15236068, 'objectForKey:'), 13293920: (15236104, 'gzipInflate'), 13293928: (15236100, 'subdataWithRange:'), 13293932: (15236076, 'initSubDerivedItems')},
        imports={13293868: (17151900, 'objc_msgSendSuper2'), 13293880: (17151904, 'objc_msgSend')},
        ivars={13293888: (17167520, 'OBJC_IVAR_$_ElevatorShaft.paintColor', 84), 13293892: (17167508, 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos', 60), 13293896: (17167516, 'OBJC_IVAR_$_ElevatorShaft.itemType', 56), 13293904: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36)},
        classes={13293876: (15253224, 'OBJC_CLASS_$_ElevatorShaft')},
        instructions=[(13293092, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13293244, 'blx r6'), (13293864, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Network restore: objc_msgSendSuper2 init + nil guard; getBytes:length: 0x28 into a stack buffer; decode lands u16/32-bit fields via the ivar slots (type@9a8 u16, lastKnownMotorPos pair@9a0, paint u16@9ac); a 0x28-extent re-read (sel 0xffe28114 getBytes:range:) + helper 0xcad974 (gzip region) + the f436b4 conditional key; return self.'),
        calls=[(13293244, 'blx r6'), (13293400, 'blx r5'), (13293512, 'blx lr'), (13293584, 'bl loc.imp.objc_msgSend'), (13293652, 'bl loc.imp.objc_msgSend'), (13293676, 'blx r2'), (13293680, 'bl 0xcad974'), (13293764, 'blx r3'), (13293780, 'blx r2'), (13293844, 'blx r2')],
        branches=[(13293272, 'bne', 13293288), (13293284, 'b', 13293856), (13293520, 'bls', 13293804)],
    ),
    dict(
        name='s_getsave',
        method='ElevatorShaft -[getSaveDict]',
        types='@8@0:4',
        start=13293976,
        end=13294868,
        disasm='disasm_elevatorshaft_getsavedict_closure.txt',
        base_add=13293992,
        base_literal=13294864,
        boundary='consecutive IMPs: [updateNetDataForClient:] follows at 0x00cadd14',
        selectors={13294800: (15236108, 'getSaveDict'), 13294820: (15236116, 'setObject:forKey:'), 13294824: (15236120, 'numberWithUnsignedInt:'), 13294840: (15236112, 'numberWithInt:')},
        imports={13294796: (17151900, 'objc_msgSendSuper2'), 13294816: (17151904, 'objc_msgSend')},
        ivars={13294808: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 13294828: (17167520, 'OBJC_IVAR_$_ElevatorShaft.paintColor', 84), 13294844: (17167508, 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos', 60), 13294856: (17167516, 'OBJC_IVAR_$_ElevatorShaft.itemType', 56)},
        classes={13294804: (15253224, 'OBJC_CLASS_$_ElevatorShaft')},
        instructions=[(13293976, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13294060, 'blx ip'), (13294792, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('getSaveDict: super stret dict; sevennumberWithInt/Unsigned pairs (ldrh u16 fields, str minY-style loads incl. the lastKnownMotorPos pair as two keys) + a conditional extra key when a field != 0 (CFString keys 0xfff436b4/c4/d4/e4/f4 - b2i key block).'),
        calls=[(13294060, 'blx ip'), (13294336, 'blx ip'), (13294372, 'blx ip'), (13294432, 'blx r3'), (13294468, 'blx ip'), (13294528, 'blx r3'), (13294564, 'blx ip'), (13294624, 'blx r3'), (13294660, 'blx ip'), (13294780, 'blx ip')],
        branches=[(13294692, 'beq', 13294784)],
    ),
    dict(
        name='s_updnet',
        method='ElevatorShaft -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=13294868,
        end=13294952,
        disasm='disasm_elevatorshaft_updatenetdata.txt',
        base_add=13294884,
        base_literal=13294948,
        boundary='consecutive IMPs: [creationNetDataForClient:] follows at 0x00cadd68',
        selectors={13294944: (15236124, 'creationNetDataForClient:')},
        imports={13294940: (17151904, 'objc_msgSend')},
        ivars={},
        classes={},
        instructions=[(13294868, 'push {fp, lr}'), (13294928, 'blx ip'), (13294936, 'pop {fp, pc}')],
        semantics=('updateNetDataForClient: single forward: [self creationNetDataForClient:arg] (sel 0xffe28128).'),
        calls=[(13294928, 'blx ip')],
        branches=[],
    ),
    dict(
        name='s_creationnet',
        method='ElevatorShaft -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=13294952,
        end=13295788,
        disasm='disasm_elevatorshaft_creationnetdata.txt',
        base_add=13294968,
        base_literal=13295784,
        boundary='ARM.exidx end 0x00cae0ac; tail gap before [remoteUpdate:] at 0x00cae218',
        selectors={13295724: (15236128, 'dynamicObjectNetData'), 13295736: (15236136, 'dictionary'), 13295744: (15236132, 'dataWithBytes:length:'), 13295772: (15236116, 'setObject:forKey:'), 13295776: (15236144, 'appendData:'), 13295780: (15236140, 'gzipDeflate')},
        imports={13295732: (17151904, 'objc_msgSend')},
        ivars={13295728: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 13295752: (17167520, 'OBJC_IVAR_$_ElevatorShaft.paintColor', 84), 13295756: (17167512, 'OBJC_IVAR_$_ElevatorShaft.solidTile', 86), 13295760: (17167508, 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos', 60), 13295764: (17167516, 'OBJC_IVAR_$_ElevatorShaft.itemType', 56)},
        classes={},
        instructions=[(13294952, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13295044, 'bl loc.imp.objc_msgSend_stret'), (13295720, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('creationNetDataForClient: super stret 0x18-byte net struct (or memset 0 when nil); fills a 0x18-byte payload from the object (u16 type@9a8, u8 solid byte, lastKnownMotorPos pair@9a0, u16 paint@9ac), memcpy assembles the frame, appendData pair, helper 0xcae0ac (gzip region), one conditional tail key (f436b4); returns the assembled data.'),
        calls=[(13295044, 'bl loc.imp.objc_msgSend_stret'), (13295080, 'bl sym.imp.memset'), (13295296, 'bl sym.imp.memcpy'), (13295452, 'blx lr'), (13295488, 'blx r3'), (13295612, 'blx ip'), (13295620, 'bl 0xcae0ac'), (13295680, 'blx lr'), (13295708, 'blx r3')],
        branches=[(13295028, 'beq', 13295052), (13295048, 'b', 13295084), (13295524, 'beq', 13295616)],
    ),
    dict(
        name='s_remoteupd',
        method='ElevatorShaft -[remoteUpdate:]',
        types='v12@0:4@8',
        start=13296152,
        end=13296660,
        disasm='disasm_elevatorshaft_remoteupdate.txt',
        base_add=13296168,
        base_literal=13296656,
        boundary='consecutive IMPs: [dealloc] follows at 0x00cae414',
        selectors={13296644: (15236092, 'getBytes:length:'), 13296652: (15236048, 'macroTiles')},
        imports={},
        ivars={13296628: (17167520, 'OBJC_IVAR_$_ElevatorShaft.paintColor', 84), 13296632: (17167512, 'OBJC_IVAR_$_ElevatorShaft.solidTile', 86), 13296636: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 13296640: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16)},
        classes={},
        instructions=[(13296152, 'push {fp, lr}'), (13296240, 'bl loc.imp.objc_msgSend'), (13296624, 'pop {fp, pc}')],
        semantics=('remoteUpdate: getBytes:length: 0x28 decode from the packet (senders payload); pos intpair static+quad reloads; tileAtWorldPositionLoaded + tileIsSolid(tile) written to the solid byte; packet u16 (strh) -> paintedIndex field@9ac; no super call in-body.'),
        calls=[(13296240, 'bl loc.imp.objc_msgSend'), (13296324, 'bl loc.imp.objc_msgSend'), (13296368, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (13296428, 'bl loc.imp.objc_msgSend'), (13296472, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (13296548, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13296560, 'bl sym.tileIsSolid_Tile_')],
        branches=[],
    ),
    dict(
        name='s_dealloc',
        method='ElevatorShaft -[dealloc]',
        types='v8@0:4',
        start=13296660,
        end=13296856,
        disasm='disasm_elevatorshaft_dealloc.txt',
        base_add=13296676,
        base_literal=13296852,
        boundary='consecutive IMPs: [draw:...] follows at 0x00cae4d8',
        selectors={13296832: (15236152, 'dealloc'), 13296844: (15236148, 'release')},
        imports={13296828: (17151900, 'objc_msgSendSuper2'), 13296840: (17151904, 'objc_msgSend')},
        ivars={13296848: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36)},
        classes={13296836: (15253224, 'OBJC_CLASS_$_ElevatorShaft')},
        instructions=[(13296660, 'push {r4, r5, r6, r7, fp, lr}'), (13296776, 'blx r5'), (13296824, 'pop {r4, r5, r6, r7, fp, pc}')],
        semantics=('Teardown: release the retained ivar object; objc_msgSendSuper2(super, dealloc).'),
        calls=[(13296776, 'blx r5'), (13296816, 'blx r2')],
        branches=[],
    ),
    dict(
        name='s_draw',
        method='ElevatorShaft -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=13296856,
        end=13299712,
        disasm='disasm_elevatorshaft_draw.txt',
        base_add=13296876,
        base_literal=13299708,
        boundary='ARM.exidx end 0x00caf000; 0x680-byte helper gap before [worldChanged:] at 0x00caf680',
        selectors={},
        imports={},
        ivars={13299672: (17167524, 'OBJC_IVAR_$_ElevatorShaft.opening', 68), 13299676: (17167528, 'OBJC_IVAR_$_ElevatorShaft.openTimer', 72), 13299680: (17167532, 'OBJC_IVAR_$_ElevatorShaft.savedDrawBuffer', 76), 13299684: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12), 13299688: (17167536, 'OBJC_IVAR_$_ElevatorShaft.savedDrawBufferIndex', 80), 13299692: (17167520, 'OBJC_IVAR_$_ElevatorShaft.paintColor', 84), 13299696: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24)},
        classes={},
        instructions=[(13296856, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13297916, 'bl method.Vector2.operator_float__'), (13299668, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Door render: gate isSolid@9a4; animation phase float@9b4 += pinchScale arg, > 5.0f -> reset to 0 + clear byte@9b0; gate byte@9b8 != 0; Vector2 pos floats (+5y); helper 0xcaf000 (quad position builder); [Vector(1,1,1,1)]; texCoordsForImageIndex with paintedIndexForImageIndex when paint@9ac != 0; phase = abs(4*field@9b4 - 1); two fillQuadBufferColored(...) submissions (20+ args, 0.51f/-0.51f/0.5f/-1.0f constants, doubled texcoords from the literal pool); return.'),
        calls=[(13297916, 'bl method.Vector2.operator_float__'), (13297952, 'bl method.Vector2.operator_float__'), (13297992, 'bl 0xcaf000'), (13298036, 'bl method.Vector.Vector_float__float__float__float_'), (13298136, 'bl 0xcaf074'), (13298184, 'bl sym.paintedIndexForImageIndex_int_'), (13298200, 'bl sym.texCoordsForImageIndex_int_'), (13299004, 'bl sym.fillQuadBufferColored_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__Vector__int__int_'), (13299660, 'bl sym.fillQuadBufferColored_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__Vector__int__int_')],
        branches=[(13297480, 'beq', 13297656), (13297552, 'ble', 13297652), (13297624, 'b', 13297652), (13297652, 'b', 13297656), (13297668, 'beq', 13299664), (13297708, 'beq', 13299664), (13297752, 'beq', 13299664), (13297820, 'bne', 13299664), (13297888, 'ble', 13299664), (13298092, 'beq', 13298192)],
    ),
    dict(
        name='s_worldchanged',
        method='ElevatorShaft -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=13301376,
        end=13302608,
        disasm='disasm_elevatorshaft_worldchanged.txt',
        base_add=13301392,
        base_literal=13302604,
        boundary='consecutive IMPs: [staticGeometryDrawQuadCountForMacroPos:] follows at 0x00cafb50',
        selectors={13302572: (15236052, 'elevatorMotorForShaftAtPos:'), 13302576: (15236056, 'pos'), 13302596: (15236048, 'macroTiles')},
        imports={},
        ivars={13302556: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52), 13302560: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13302564: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 13302580: (17167508, 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos', 60), 13302584: (17167512, 'OBJC_IVAR_$_ElevatorShaft.solidTile', 86), 13302588: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 13302600: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49)},
        classes={},
        instructions=[(13301376, 'push {r4, r5, fp, lr}'), (13301852, 'bl loc.imp.objc_msgSend'), (13302552, 'pop {r4, r5, fp, pc}')],
        semantics=('worldChanged: external intpair-vector iteration (8-byte steps); gate isNet; if change.x == pos.x: recompute the motor position ([... sel 0xffe280e0] intpair, stret with memset fallback) -> lastKnownMotorPos@60; tileAtWorldPositionLoaded + tileIsSolid vs stored solid byte: if changed -> rewrite the byte, reloadDrawBlockDynamicObjectStaticGeometryForTile + reloadDrawBlockDynamicObjectQuadsForTile, and when !isNet set updateNeedsToBeSent.'),
        calls=[(13301852, 'bl loc.imp.objc_msgSend'), (13301952, 'bl loc.imp.objc_msgSend_stret'), (13301988, 'bl sym.imp.memset'), (13302084, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13302096, 'bl sym.tileIsSolid_Tile_'), (13302256, 'bl loc.imp.objc_msgSend'), (13302300, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (13302360, 'bl loc.imp.objc_msgSend'), (13302404, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_')],
        branches=[(13301440, 'beq', 13301448), (13301444, 'b', 13302548), (13301684, 'beq', 13302548), (13301756, 'bne', 13302484), (13301872, 'beq', 13302012), (13301936, 'beq', 13301960), (13301956, 'b', 13301992), (13302140, 'beq', 13302480), (13302440, 'bne', 13302476), (13302476, 'b', 13302480), (13302480, 'b', 13302484), (13302484, 'b', 13302488), (13302544, 'b', 13301532)],
    ),
    dict(
        name='s_sgdq',
        method='ElevatorShaft -[staticGeometryDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=13302608,
        end=13302712,
        disasm='disasm_elevatorshaft_staticgeometrydrawquadcount.txt',
        base_add=13302620,
        base_literal=13302708,
        boundary='consecutive IMPs: [addDrawQuadData:fromIndex:forMacroPos:] follows at 0x00cafbb8',
        selectors={},
        imports={},
        ivars={13302704: (17167512, 'OBJC_IVAR_$_ElevatorShaft.solidTile', 86)},
        classes={},
        instructions=[(13302608, 'push {fp, lr}'), (13302700, 'pop {fp, pc}')],
        semantics=('staticGeometryDrawQuadCountForMacroPos: = solid byte? 0 : 2 (doors draw two quads when open).'),
        calls=[],
        branches=[(13302668, 'beq', 13302684), (13302680, 'b', 13302692)],
    ),
    dict(
        name='s_addquad',
        method='ElevatorShaft -[addDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=13302712,
        end=13304724,
        disasm='disasm_elevatorshaft_adddrawquaddata.txt',
        base_add=13302732,
        base_literal=13304720,
        boundary='consecutive IMPs: [staticGeometryDrawCubeCount] follows at 0x00cb0394',
        selectors={},
        imports={},
        ivars={13304684: (17167512, 'OBJC_IVAR_$_ElevatorShaft.solidTile', 86), 13304688: (17167520, 'OBJC_IVAR_$_ElevatorShaft.paintColor', 84), 13304692: (17167536, 'OBJC_IVAR_$_ElevatorShaft.savedDrawBufferIndex', 80), 13304696: (17167532, 'OBJC_IVAR_$_ElevatorShaft.savedDrawBuffer', 76), 13304700: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24), 13304708: (17167528, 'OBJC_IVAR_$_ElevatorShaft.openTimer', 72), 13304712: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12)},
        classes={},
        instructions=[(13302712, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13303000, 'bl method.Vector.Vector_float__float__float__float_'), (13304680, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('addDrawQuadData:fromIndex:forMacroPos: solid -> 0 + clears the 9b8/9bc fields; else stashes the macroPos pair into 9b8/9bc; Vector(1,1,1,1); tex 583 (paintedIndexForImageIndex when paint set); phase = abs(4*field@9b4 - 1); helper 0xcaf000; two fillQuadBufferColored submissions, index+2 returned.'),
        calls=[(13303000, 'bl method.Vector.Vector_float__float__float__float_'), (13303100, 'bl 0xcaf074'), (13303148, 'bl sym.paintedIndexForImageIndex_int_'), (13303164, 'bl sym.texCoordsForImageIndex_int_'), (13303252, 'bl method.Vector2.operator_float__'), (13303284, 'bl method.Vector2.operator_float__'), (13303324, 'bl 0xcaf000'), (13304016, 'bl sym.fillQuadBufferColored_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__Vector__int__int_'), (13304648, 'bl sym.fillQuadBufferColored_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__Vector__int__int_')],
        branches=[(13302800, 'beq', 13302892), (13302864, 'b', 13304672), (13303056, 'beq', 13303156)],
    ),
    dict(
        name='s_sgcdc',
        method='ElevatorShaft -[staticGeometryDrawCubeCount]',
        types='i8@0:4',
        start=13304724,
        end=13304816,
        disasm='disasm_elevatorshaft_staticgeometrydrawcubecount.txt',
        base_add=13304732,
        base_literal=13304812,
        boundary='consecutive IMPs: [freeblockCreationItemType] follows at 0x00cb03f0',
        selectors={},
        imports={},
        ivars={13304808: (17167512, 'OBJC_IVAR_$_ElevatorShaft.solidTile', 86)},
        classes={},
        instructions=[(13304724, 'sub sp, sp, 0xc'), (13304804, 'bx lr')],
        semantics=('staticGeometryDrawCubeCount: = solid byte? 0 : 3 (frame + rail cubes when open).'),
        calls=[],
        branches=[(13304772, 'beq', 13304788), (13304784, 'b', 13304796)],
    ),
    dict(
        name='s_fbitem',
        method='ElevatorShaft -[freeblockCreationItemType]',
        types='i8@0:4',
        start=13304816,
        end=13304876,
        disasm='disasm_elevatorshaft_freeblockcreationitemtype.txt',
        base_add=13304824,
        base_literal=13304872,
        boundary='consecutive IMPs: [freeBlockCreationSaveDict] follows at 0x00cb042c',
        selectors={},
        imports={},
        ivars={13304868: (17167516, 'OBJC_IVAR_$_ElevatorShaft.itemType', 56)},
        classes={},
        instructions=[(13304816, 'sub sp, sp, 8'), (13304864, 'bx lr')],
        semantics=('freeblockCreationItemType = ivar load (the freeblock item id for placement).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='s_fbsave',
        method='ElevatorShaft -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=13304876,
        end=13304952,
        disasm='disasm_elevatorshaft_freeblockcreationsavedict.txt',
        base_add=13304892,
        base_literal=13304948,
        boundary='consecutive IMPs: [freeBlockCreationDataA] follows at 0x00cb0478',
        selectors={13304944: (15236108, 'getSaveDict')},
        imports={13304940: (17151904, 'objc_msgSend')},
        ivars={},
        classes={},
        instructions=[(13304876, 'push {fp, lr}'), (13304928, 'blx r3'), (13304936, 'pop {fp, pc}')],
        semantics=('freeBlockCreationSaveDict = [self getSaveDict] forward (sel 0xffe28118).'),
        calls=[(13304928, 'blx r3')],
        branches=[],
    ),
    dict(
        name='s_fba',
        method='ElevatorShaft -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=13304952,
        end=13304980,
        disasm='disasm_elevatorshaft_freeblockcreationdataa.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [freeBlockCreationDataB] follows at 0x00cb0494',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13304952, 'sub sp, sp, 8'), (13304976, 'bx lr')],
        semantics=('freeBlockCreationDataA = 0 (uxth).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='s_fbb',
        method='ElevatorShaft -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=13304980,
        end=13305008,
        disasm='disasm_elevatorshaft_freeblockcreationdatab.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [addDrawCubeData:fromIndex:] follows at 0x00cb04b0',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13304980, 'sub sp, sp, 8'), (13305004, 'bx lr')],
        semantics=('freeBlockCreationDataB = 0 (uxth).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='s_addcube',
        method='ElevatorShaft -[addDrawCubeData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=13305008,
        end=13308216,
        disasm='disasm_elevatorshaft_adddrawcubedata.txt',
        base_add=13305032,
        base_literal=13308212,
        boundary='consecutive IMPs: [open] follows at 0x00cb1138',
        selectors={13308208: (15236156, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:paintColor:')},
        imports={},
        ivars={13308184: (17167512, 'OBJC_IVAR_$_ElevatorShaft.solidTile', 86), 13308188: (17167520, 'OBJC_IVAR_$_ElevatorShaft.paintColor', 84), 13308192: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13308204: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12)},
        classes={13308200: (15250884, 'OBJC_CLASS_$_DrawCube')},
        instructions=[(13305008, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13305152, 'bl method.Vector.Vector_float__float__float__float_'), (13308160, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('addDrawCubeData:fromIndex: solid -> 0; three fillBuffer (20-arg) cube submissions: two with texture 583 (paintedIndexForImageIndex when paint set) and one with texCoordsForImageIndex(0x73 = 115); positions +5y with z = -1.5f via helper 0xcaf000; constants 0.95f/0.55f/0.05f/0.1f/0.2f/-1.95f/0.7f/0.5f/1.0f; returns index+3.'),
        calls=[(13305152, 'bl method.Vector.Vector_float__float__float__float_'), (13305252, 'bl 0xcaf074'), (13305300, 'bl sym.paintedIndexForImageIndex_int_'), (13305316, 'bl sym.texCoordsForImageIndex_int_'), (13305472, 'bl 0xcaf000'), (13306244, 'bl loc.imp.objc_msgSend'), (13306324, 'bl 0xcaf000'), (13307124, 'bl loc.imp.objc_msgSend'), (13307148, 'bl sym.texCoordsForImageIndex_int_'), (13307280, 'bl 0xcaf000'), (13308124, 'bl loc.imp.objc_msgSend')],
        branches=[(13305084, 'beq', 13305104), (13305096, 'b', 13308148), (13305208, 'beq', 13305308), (13307296, 'b', 13307304)],
    ),
    dict(
        name='s_open',
        method='ElevatorShaft -[open]',
        types='v8@0:4',
        start=13308216,
        end=13308280,
        disasm='disasm_elevatorshaft_open.txt',
        base_add=13308224,
        base_literal=13308276,
        boundary='consecutive IMPs: [removeFromMacroBlock] follows at 0x00cb1178',
        selectors={},
        imports={},
        ivars={13308272: (17167524, 'OBJC_IVAR_$_ElevatorShaft.opening', 68)},
        classes={},
        instructions=[(13308216, 'sub sp, sp, 8'), (13308268, 'bx lr')],
        semantics=('open: stores byte 1 to the 9b0 field (the door-open flag read by draw/sgcdc).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='s_rmmacro',
        method='ElevatorShaft -[removeFromMacroBlock]',
        types='v8@0:4',
        start=13308280,
        end=13308660,
        disasm='disasm_elevatorshaft_removefrommacroblock.txt',
        base_add=13308296,
        base_literal=13308656,
        boundary='consecutive IMPs: [paint:] follows at 0x00cb12f4',
        selectors={13308632: (15236160, 'removeFromMacroBlock'), 13308652: (15236048, 'macroTiles')},
        imports={13308628: (17151900, 'objc_msgSendSuper2')},
        ivars={13308640: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13308648: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={13308636: (15253224, 'OBJC_CLASS_$_ElevatorShaft')},
        instructions=[(13308280, 'push {r4, sl, fp, lr}'), (13308400, 'bl loc.imp.objc_msgSend'), (13308624, 'pop {r4, sl, fp, pc}')],
        semantics=('removeFromMacroBlock: reloadDrawBlockDynamicObjectStaticGeometryForTile + reloadDrawBlockDynamicObjectQuadsForTile for the object position, then objc_msgSendSuper2(super, removeFromMacroBlock).'),
        calls=[(13308400, 'bl loc.imp.objc_msgSend'), (13308444, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (13308504, 'bl loc.imp.objc_msgSend'), (13308548, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (13308616, 'blx r3')],
        branches=[],
    ),
    dict(
        name='s_paint',
        method='ElevatorShaft -[paint:]',
        types='v12@0:4S8',
        start=13308660,
        end=13309196,
        disasm='disasm_elevatorshaft_paint.txt',
        base_add=13308676,
        base_literal=13309192,
        boundary='consecutive IMPs: [isPaintable] follows at 0x00cb150c',
        selectors={13309168: (15236048, 'macroTiles'), 13309184: (15236164, 'objectType'), 13309188: (15236168, 'dynamicWorldChangedAtPos:objectType:')},
        imports={},
        ivars={13309148: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52), 13309152: (17167520, 'OBJC_IVAR_$_ElevatorShaft.paintColor', 84), 13309160: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13309164: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 13309172: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49), 13309180: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8)},
        classes={},
        instructions=[(13308660, 'push {r4, sl, fp, lr}'), (13308808, 'bl loc.imp.objc_msgSend'), (13309144, 'pop {r4, sl, fp, pc}')],
        semantics=('paint: stores the u16 arg via slot 0xfffff9ac (paint field); static+quad reloads; if !isNet: set updateNeedsToBeSent and replay via the change pair (sels 0xffe28150/0xffe28154, objc_msgSend_stret style).'),
        calls=[(13308808, 'bl loc.imp.objc_msgSend'), (13308852, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (13308912, 'bl loc.imp.objc_msgSend'), (13308956, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (13309100, 'bl loc.imp.objc_msgSend'), (13309136, 'bl loc.imp.objc_msgSend')],
        branches=[(13308992, 'bne', 13309140)],
    ),
    dict(
        name='s_ispaint',
        method='ElevatorShaft -[isPaintable]',
        types='c8@0:4',
        start=13309196,
        end=13309224,
        disasm='disasm_elevatorshaft_ispaintable.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [occupiesNormalContents] follows at 0x00cb1528',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13309196, 'sub sp, sp, 8'), (13309220, 'bx lr')],
        semantics=('isPaintable = 1.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='s_occnormal',
        method='ElevatorShaft -[occupiesNormalContents]',
        types='c8@0:4',
        start=13309224,
        end=13309252,
        disasm='disasm_elevatorshaft_occupiesnormalcontents.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [lastKnownMotorPos] follows at 0x00cb1544',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13309224, 'sub sp, sp, 8'), (13309248, 'bx lr')],
        semantics=('occupiesNormalContents = 1.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='s_lastmotor',
        method='ElevatorShaft -[lastKnownMotorPos]',
        types='{?=ii}8@0:4',
        start=13309252,
        end=13309348,
        disasm='disasm_elevatorshaft_lastknownmotorpos.txt',
        base_add=13309268,
        base_literal=13309344,
        boundary='ARM.exidx end 0x00cb15a4; class tail follows',
        selectors={},
        imports={},
        ivars={13309340: (17167508, 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos', 60)},
        classes={},
        instructions=[(13309252, 'push {r4, r5, fp, lr}'), (13309328, 'bl sym.imp.objc_copyStruct'), (13309336, 'pop {r4, r5, fp, pc}')],
        semantics=('lastKnownMotorPos = objc_copyStruct accessor: copies the 8-byte intpair from ElevatorShaft.lastKnownMotorPos@60 (isa/source pointer, length/align flags {8, 1, 0}); direct ivar offset - no base needed.'),
        calls=[(13309328, 'bl sym.imp.objc_copyStruct')],
        branches=[],
    ),]

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

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    dynsym = {}
    for sec in ELFFile(io.BytesIO(data)).iter_sections():
        if sec.name == '.dynsym':
            for s in sec.iter_symbols():
                if s['st_value']:
                    dynsym.setdefault(s['st_value'], s.name)

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

        for cell, (expected_slot, expected_symbol) in spec.get('classes', {}).items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: class cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            got = dynsym.get(entry, '')
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: class drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got}

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

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

        listed_branches = {(a, m.group(1), int(m.group(2), 16))
                           for a, ins in inrange.items()
                           for m in [re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)]
                           if m and m.group(1) not in ('bl', 'blx')}
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
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'ElevatorShaft closure: init/save/net quartets (rail shaft, objectType 0x38), solid-byte + lastKnownMotorPos tracking, door draw (animation phase 0..5, fillQuadBufferColored), static-geometry quads (2) + cubes (3), paint/open/isPaintable, removeFromMacroBlock, updateNetDataForClient forward (26 bodies)',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'elevator_shaft.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale elevator_shaft.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
