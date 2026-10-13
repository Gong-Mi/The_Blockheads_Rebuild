#!/usr/bin/env python3
"""Hash-gated recovery of the Wire class closure (non-render).

18 bodies, 2104 instruction words total, from the pinned original libApplication.so (1.7.6, armeabi-v7a):
initSubDerivedItems (42w), objectType (7w), initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient: (178w),
initWithWorld:dynamicWorld:saveDict:cache: (200w), initWithWorld:dynamicWorld:cache:netData: (207w), dealloc (49w), getSaveDict (189w),
updateNetDataForClient: (21w), creationNetDataForClient: (193w), remoteUpdate: (116w), freeblockCreationItemType (15w),
freeBlockCreationSaveDict (7w), freeBlockCreationDataA (7w), freeBlockCreationDataB (7w), worldChanged: (720w),
removeFromMacroBlock (66w), occupiesForegroundContents (40w), occupiesNormalContents (40w).
Every instruction word is re-verified; tool refuses to emit on drift.
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
    'bl 0x950688': 0X00950688,
    'bl 0x950dbc': 0X00950DBC,
    'bl 0x951ef0': 0X00951EF0,
    'bl loc.imp.objc_msgSend': 0X001C281C,
    'bl loc.imp.objc_msgSendSuper2': 0X001C29FC,
    'bl loc.imp.objc_msgSend_stret': 0X001C2918,
    'bl sym.imp.__aeabi_idiv': 0X001C3728,
    'bl sym.imp.memcpy': 0X001C2894,
    'bl sym.imp.memset': 0X001C2924,
    'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_': 0X00A19598,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0X00A12F24,
    'bl sym.tileIsSolid_Tile_': 0X00A1179C,
    'bl sym.tileIsWater_Tile_': 0X00A11690,
}

SPECS = [
    dict(
        name='w_subderived',
        method='Wire -[initSubDerivedItems]',
        types='v8@0:4',
        start=9764000,
        end=9764168,
        disasm='disasm_wire_initsubderiveditems.txt',
        base_add=9764032,
        base_literal=9764156,
        boundary='consecutive IMPs: [objectType] follows at 0x0094fd48',
        selectors={9764164: (15219192, 'macroTiles')},
        imports={},
        ivars={9764152: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 9764160: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={},
        instructions=[(9764000, 'push {fp, lr}'), (9764096, 'bl loc.imp.objc_msgSend'), (9764140, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (9764148, 'pop {fp, pc}')],
        semantics=("Reload the wire's static geometry: reads the pos {x,y} pair (DynamicObject.pos@16 writeback pair) and the owning world@4; one objc_msgSend for 'macroTiles'; then reloadDrawBlockDynamicObjectStaticGeometryForTile(posPair, macroTiles, world)."),
        calls=[(9764096, 'bl loc.imp.objc_msgSend'), (9764140, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_')],
        branches=[],
    ),
    dict(
        name='w_objtype',
        method='Wire -[objectType]',
        types='i8@0:4',
        start=9764168,
        end=9764196,
        disasm='disasm_wire_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:] follows at 0x0094fd64',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9764168, 'sub sp, sp, 8'), (9764172, 'movw r2, 0x26'), (9764192, 'bx lr')],
        semantics=('return 0x26 - the wire dynamic-object type tag (same tag used by DynamicWorld wireAtPos: / addWireAtPos: in the electricity net-sync batch).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='w_initpos',
        method='Wire -[initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:]',
        types='@40@0:4@8@12{?=ii}16@24i28@32@36',
        start=9764196,
        end=9764908,
        disasm='disasm_wire_initwithworld_position.txt',
        base_add=9764212,
        base_literal=9764904,
        boundary='consecutive IMPs: [initWithWorld:dynamicWorld:saveDict:cache:] follows at 0x0095002c',
        selectors={9764868: (15219196, 'initWithWorld:dynamicWorld:atPosition:cache:'), 9764884: (15219204, 'objectForKey:'), 9764892: (15219200, 'retain'), 9764896: (15219212, 'initSubDerivedItems'), 9764900: (15219208, 'updateWireConfiguration')},
        imports={9764880: (17151904, 'objc_msgSend')},
        ivars={9764872: (17163008, 'OBJC_IVAR_$_Wire.itemType', 56), 9764888: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36)},
        classes={9764860: (15252928, 'OBJC_CLASS_$_Wire')},
        instructions=[(9764196, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9764396, 'bl loc.imp.objc_msgSendSuper2'), (9764620, 'blx r3'), (9764532, 'blx r2'), (9764856, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=("Full wire init: objc_msgSendSuper2(super, 'initWithWorld:dynamicWorld:atPosition:cache:'); nil -> nil; Wire.itemType@56 = type arg; saveDict branch (retain / objectForKey: pair) vs no-saveDict branch; finishing calls [self initSubDerivedItems] + [self updateWireConfiguration]; return self."),
        calls=[(9764396, 'bl loc.imp.objc_msgSendSuper2'), (9764532, 'blx r2'), (9764620, 'blx r3'), (9764720, 'blx lr'), (9764736, 'blx r2'), (9764816, 'blx r3'), (9764836, 'blx r2')],
        branches=[(9764424, 'bne', 9764440), (9764436, 'b', 9764848), (9764484, 'beq', 9764560), (9764556, 'b', 9764764), (9764632, 'beq', 9764760), (9764760, 'b', 9764764)],
    ),
    dict(
        name='w_initsave',
        method='Wire -[initWithWorld:dynamicWorld:saveDict:cache:]',
        types='@24@0:4@8@12@16@20',
        start=9764908,
        end=9765708,
        disasm='disasm_wire_initwithworld_savedict.txt',
        base_add=9764924,
        base_literal=9765704,
        boundary='consecutive IMPs: [initWithWorld:dynamicWorld:cache:netData:] follows at 0x0095034c',
        selectors={9765644: (15219216, 'initWithWorld:dynamicWorld:saveDict:cache:'), 9765660: (15219220, 'intValue'), 9765668: (15219204, 'objectForKey:'), 9765688: (15219212, 'initSubDerivedItems'), 9765696: (15219200, 'retain')},
        imports={9765640: (17151900, 'objc_msgSendSuper2'), 9765656: (17151904, 'objc_msgSend')},
        ivars={9765652: (17163004, 'OBJC_IVAR_$_Wire.currentSolidConfiguration', 64), 9765672: (17163000, 'OBJC_IVAR_$_Wire.currentConfiguration', 60), 9765680: (17163008, 'OBJC_IVAR_$_Wire.itemType', 56), 9765692: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36)},
        classes={9765648: (15252928, 'OBJC_CLASS_$_Wire')},
        instructions=[(9764908, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9765060, 'blx r6'), (9765240, 'blx r8'), (9765424, 'movw r0, 1'), (9765560, 'blx r5'), (9765636, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=("Save-load init: objc_msgSendSuper2(super, 'initWithWorld:dynamicWorld:saveDict:cache:'); nil -> nil; restores Wire.itemType@56 / currentConfiguration@60 / currentSolidConfiguration@64 from the save dict (objectForKey: + intValue + retain chains); a field reading 0 is forced to 1; [self initSubDerivedItems]; return self."),
        calls=[(9765060, 'blx r6'), (9765240, 'blx r8'), (9765256, 'blx r2'), (9765300, 'blx r3'), (9765316, 'blx r2'), (9765360, 'blx r3'), (9765376, 'blx r2'), (9765560, 'blx r5'), (9765576, 'blx r2'), (9765616, 'blx r3')],
        branches=[(9765088, 'bne', 9765104), (9765100, 'b', 9765628), (9765420, 'bne', 9765456)],
    ),
    dict(
        name='w_initnet',
        method='Wire -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=9765708,
        end=9766536,
        disasm='disasm_wire_initwithworld_netdata.txt',
        base_add=9765724,
        base_literal=9766532,
        boundary='body 0x0095034c..0x00950688; private helper 0x00950688..0x009506ac (IMP gap) excluded',
        selectors={9766468: (15219224, 'initWithWorld:dynamicWorld:cache:netData:'), 9766480: (15219232, 'length'), 9766496: (15219228, 'getBytes:length:'), 9766504: (15219200, 'retain'), 9766512: (15219204, 'objectForKey:'), 9766516: (15219240, 'gzipInflate'), 9766524: (15219236, 'subdataWithRange:'), 9766528: (15219212, 'initSubDerivedItems')},
        imports={9766464: (17151900, 'objc_msgSendSuper2'), 9766476: (17151904, 'objc_msgSend')},
        ivars={9766484: (17163004, 'OBJC_IVAR_$_Wire.currentSolidConfiguration', 64), 9766488: (17163000, 'OBJC_IVAR_$_Wire.currentConfiguration', 60), 9766492: (17163008, 'OBJC_IVAR_$_Wire.itemType', 56), 9766500: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36)},
        classes={9766472: (15252928, 'OBJC_CLASS_$_Wire')},
        instructions=[(9765708, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9765860, 'blx r6'), (9766020, 'ldrh r0, [sp, 0x80]'), (9766276, 'bl 0x950688'), (9766180, 'bl loc.imp.objc_msgSend'), (9766460, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=("Net init: objc_msgSendSuper2(super, 'initWithWorld:dynamicWorld:cache:netData:'); nil -> nil; gzipInflate -> subdataWithRange: -> length / getBytes:length: -> unpack {uint16 itemType@56, u8 currentConfiguration@60, u8 currentSolidConfiguration@64}; segments beyond 0x20 go through the private helper 0x950688 (IMP gap, out of body); [self initSubDerivedItems]; return self."),
        calls=[(9765860, 'blx r6'), (9766016, 'blx r5'), (9766108, 'blx lr'), (9766180, 'bl loc.imp.objc_msgSend'), (9766248, 'bl loc.imp.objc_msgSend'), (9766272, 'blx r2'), (9766276, 'bl 0x950688'), (9766360, 'blx r3'), (9766376, 'blx r2'), (9766440, 'blx r2')],
        branches=[(9765888, 'bne', 9765904), (9765900, 'b', 9766452), (9766116, 'bls', 9766400)],
    ),
    dict(
        name='w_dealloc',
        method='Wire -[dealloc]',
        types='v8@0:4',
        start=9766572,
        end=9766768,
        disasm='disasm_wire_dealloc.txt',
        base_add=9766588,
        base_literal=9766764,
        boundary='consecutive IMPs: [getSaveDict] follows at 0x00950770',
        selectors={9766744: (15219248, 'dealloc'), 9766756: (15219244, 'release')},
        imports={9766740: (17151900, 'objc_msgSendSuper2'), 9766752: (17151904, 'objc_msgSend')},
        ivars={9766760: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36)},
        classes={9766748: (15252928, 'OBJC_CLASS_$_Wire')},
        instructions=[(9766572, 'push {r4, r5, r6, r7, fp, lr}'), (9766688, 'blx r5'), (9766728, 'blx r2'), (9766736, 'pop {r4, r5, r6, r7, fp, pc}')],
        semantics=('[self.ownerID@36 release]; objc_msgSendSuper2(super, dealloc).'),
        calls=[(9766688, 'blx r5'), (9766728, 'blx r2')],
        branches=[],
    ),
    dict(
        name='w_getsave',
        method='Wire -[getSaveDict]',
        types='@8@0:4',
        start=9766768,
        end=9767524,
        disasm='disasm_wire_getsavedict_closure.txt',
        base_add=9766784,
        base_literal=9767520,
        boundary='consecutive IMPs: [updateNetDataForClient:] follows at 0x00950a64',
        selectors={9767464: (15219252, 'getSaveDict'), 9767484: (15219260, 'setObject:forKey:'), 9767488: (15219256, 'numberWithInt:')},
        imports={9767460: (17151900, 'objc_msgSendSuper2'), 9767480: (17151904, 'objc_msgSend')},
        ivars={9767472: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 9767492: (17163004, 'OBJC_IVAR_$_Wire.currentSolidConfiguration', 64), 9767504: (17163000, 'OBJC_IVAR_$_Wire.currentConfiguration', 60), 9767512: (17163008, 'OBJC_IVAR_$_Wire.itemType', 56)},
        classes={9767468: (15252928, 'OBJC_CLASS_$_Wire')},
        instructions=[(9766768, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9766852, 'blx ip'), (9767192, 'blx r3'), (9767456, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('dict = [super getSaveDict] (stret); [dict setObject:[NSNumber numberWithInt:itemType@56] forKey:] plus currentConfiguration@60 / currentSolidConfiguration@64; when ownerID@36 non-nil an extra setObject:forKey:; return dict.'),
        calls=[(9766852, 'blx ip'), (9767096, 'blx ip'), (9767132, 'blx ip'), (9767192, 'blx r3'), (9767228, 'blx ip'), (9767288, 'blx r3'), (9767324, 'blx ip'), (9767444, 'blx ip')],
        branches=[(9767356, 'beq', 9767448)],
    ),
    dict(
        name='w_updnet',
        method='Wire -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=9767524,
        end=9767608,
        disasm='disasm_wire_updatenetdata.txt',
        base_add=9767540,
        base_literal=9767604,
        boundary='consecutive IMPs: [creationNetDataForClient:] follows at 0x00950ab8',
        selectors={9767600: (15219264, 'creationNetDataForClient:')},
        imports={9767596: (17151904, 'objc_msgSend')},
        ivars={},
        classes={},
        instructions=[(9767524, 'push {fp, lr}'), (9767584, 'blx ip'), (9767592, 'pop {fp, pc}')],
        semantics=('Forwarder: updateNetDataForClient: = [self creationNetDataForClient:client] (single objc_msgSend).'),
        calls=[(9767584, 'blx ip')],
        branches=[],
    ),
    dict(
        name='w_creationnet',
        method='Wire -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=9767608,
        end=9768380,
        disasm='disasm_wire_creationnetdata.txt',
        base_add=9767624,
        base_literal=9768376,
        boundary='body 0x00950ab8..0x00950dbc; private helper 0x00950dbc..0x00950f28 (IMP gap) excluded',
        selectors={9768320: (15219268, 'dynamicObjectNetData'), 9768332: (15219276, 'dictionary'), 9768340: (15219272, 'dataWithBytes:length:'), 9768364: (15219260, 'setObject:forKey:'), 9768368: (15219284, 'appendData:'), 9768372: (15219280, 'gzipDeflate')},
        imports={9768328: (17151904, 'objc_msgSend')},
        ivars={9768324: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 9768348: (17163004, 'OBJC_IVAR_$_Wire.currentSolidConfiguration', 64), 9768352: (17163000, 'OBJC_IVAR_$_Wire.currentConfiguration', 60), 9768356: (17163008, 'OBJC_IVAR_$_Wire.itemType', 56)},
        classes={},
        instructions=[(9767608, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9767700, 'bl loc.imp.objc_msgSend_stret'), (9767736, 'bl sym.imp.memset'), (9767936, 'bl sym.imp.memcpy'), (9768216, 'bl 0x950dbc'), (9768316, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=("Net data builder: reads the client's 'dynamicObjectNetData' blob (0x18 bytes via objc_msgSend_stret; memset 0 when client is nil); fills {uint16 itemType@56, u8 currentConfiguration@60, u8 currentSolidConfiguration@64}; wraps via dataWithBytes:length: / appendData: + gzipDeflate into the dictionary record; non-zero field -> extra setObject:forKey:; private helper 0x950dbc (IMP gap, out of body); returns the assembled dict."),
        calls=[(9767700, 'bl loc.imp.objc_msgSend_stret'), (9767736, 'bl sym.imp.memset'), (9767936, 'bl sym.imp.memcpy'), (9768048, 'blx ip'), (9768084, 'blx r3'), (9768208, 'blx ip'), (9768216, 'bl 0x950dbc'), (9768276, 'blx lr'), (9768304, 'blx r3')],
        branches=[(9767684, 'beq', 9767708), (9767704, 'b', 9767740), (9768120, 'beq', 9768212)],
    ),
    dict(
        name='w_remoteupd',
        method='Wire -[remoteUpdate:]',
        types='v12@0:4@8',
        start=9768744,
        end=9769208,
        disasm='disasm_wire_remoteupdate.txt',
        base_add=9768760,
        base_literal=9769204,
        boundary='consecutive IMPs: [draw:projectionMatrix:...] follows at 0x009510f8',
        selectors={9769164: (15219288, 'remoteUpdate:'), 9769180: (15219228, 'getBytes:length:'), 9769200: (15219192, 'macroTiles')},
        imports={9769160: (17151900, 'objc_msgSendSuper2'), 9769176: (17151904, 'objc_msgSend')},
        ivars={9769172: (17163000, 'OBJC_IVAR_$_Wire.currentConfiguration', 60), 9769184: (17163004, 'OBJC_IVAR_$_Wire.currentSolidConfiguration', 64), 9769192: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 9769196: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={9769168: (15252928, 'OBJC_CLASS_$_Wire')},
        instructions=[(9768744, 'push {r4, r5, fp, lr}'), (9768836, 'blx lr'), (9768904, 'blx ip'), (9769148, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (9769156, 'pop {r4, r5, fp, pc}')],
        semantics=('[super remoteUpdate:data]; [data getBytes:buf length:0x20]; when buf {cfg,solid} != currentConfiguration@60 / currentSolidConfiguration@64 -> write both + rebuild static geometry (macroTiles + reloadDrawBlockDynamicObjectStaticGeometryForTile on the pos pair); unchanged -> no-op.'),
        calls=[(9768836, 'blx lr'), (9768904, 'blx ip'), (9769104, 'bl loc.imp.objc_msgSend'), (9769148, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_')],
        branches=[(9768936, 'bne', 9768980), (9768976, 'beq', 9769152)],
    ),
    dict(
        name='w_fbitem',
        method='Wire -[freeblockCreationItemType]',
        types='i8@0:4',
        start=9769760,
        end=9769820,
        disasm='disasm_wire_freeblockcreationitemtype.txt',
        base_add=9769768,
        base_literal=9769816,
        boundary='consecutive IMPs: [freeBlockCreationSaveDict] follows at 0x0095135c',
        selectors={},
        imports={},
        ivars={9769812: (17163008, 'OBJC_IVAR_$_Wire.itemType', 56)},
        classes={},
        instructions=[(9769760, 'sub sp, sp, 8'), (9769800, 'ldr r0, [r0]'), (9769808, 'bx lr')],
        semantics=('return *(int *)(self + 56) - Wire.itemType@56 leaf getter.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='w_fbsave',
        method='Wire -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=9769820,
        end=9769848,
        disasm='disasm_wire_freeblockcreationsavedict.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [freeBlockCreationDataA] follows at 0x00951378',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9769820, 'sub sp, sp, 8'), (9769824, 'movw r2, 0'), (9769836, 'mov r0, r2'), (9769844, 'bx lr')],
        semantics=('return nil (no free-block save dict for wires).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='w_fba',
        method='Wire -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=9769848,
        end=9769876,
        disasm='disasm_wire_freeblockcreationdataa.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [freeBlockCreationDataB] follows at 0x00951394',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9769848, 'sub sp, sp, 8'), (9769852, 'movw r2, 0'), (9769864, 'uxth r0, r2'), (9769872, 'bx lr')],
        semantics=('return 0 (uxth) - freeBlockCreationDataA constant.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='w_fbb',
        method='Wire -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=9769876,
        end=9769904,
        disasm='disasm_wire_freeblockcreationdatab.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [worldChanged:] follows at 0x009513b0',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9769876, 'sub sp, sp, 8'), (9769880, 'movw r2, 0'), (9769892, 'uxth r0, r2'), (9769900, 'bx lr')],
        semantics=('return 0 (uxth) - freeBlockCreationDataB constant.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='w_worldchanged',
        method='Wire -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=9769904,
        end=9772784,
        disasm='disasm_wire_worldchanged.txt',
        base_add=9769920,
        base_literal=9772780,
        boundary='body 0x009513b0..0x00951ef0; helper 0x00951ef0..0x00951f2c (IMP gap) excluded',
        selectors={9772724: (15219304, 'worldWidthMacro'), 9772748: (15219208, 'updateWireConfiguration'), 9772752: (15219292, 'isClient'), 9772764: (15219300, 'removeStandardObject:'), 9772772: (15219296, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:')},
        imports={9772744: (17151904, 'objc_msgSend')},
        ivars={9772708: (17163008, 'OBJC_IVAR_$_Wire.itemType', 56), 9772712: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 9772716: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 9772740: (17163000, 'OBJC_IVAR_$_Wire.currentConfiguration', 60), 9772756: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 9772760: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48)},
        classes={},
        instructions=[(9769904, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9769960, 'cmp r0, 0xb2'), (9770408, 'bl sym.tileIsWater_Tile_'), (9771756, 'bl sym.tileIsSolid_Tile_'), (9771300, 'bl 0x951ef0'), (9770484, 'blx r2'), (9772704, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Gate: itemType@56 != 0xb2 -> return. Loop over the changed {x,y} vector (8-byte stride) with wrap-aware distance normalization ((macro-size value << 5)/2 via __aeabi_idiv; helper 0x951ef0 in the IMP tail, out of body). Own-cell case (x,y == pos@16): tileAtWorldPositionLoaded + tileIsWater + workbench gate -> createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead: + removeStandardObject: (needsRemoved@48; isClient via dynamicWorld@8). Neighbor case: four probes around (x,y) with tile[1]==2 / non-nil / !tileIsSolid / tile[3]!=0x60 / tile[3]!=0x2e screens -> [self updateWireConfiguration].'),
        calls=[(9770396, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9770408, 'bl sym.tileIsWater_Tile_'), (9770484, 'blx r2'), (9770724, 'bl loc.imp.objc_msgSend'), (9770764, 'blx ip'), (9770864, 'bl loc.imp.objc_msgSend'), (9770888, 'bl sym.imp.__aeabi_idiv'), (9770984, 'bl loc.imp.objc_msgSend'), (9771104, 'bl loc.imp.objc_msgSend'), (9771120, 'bl sym.imp.__aeabi_idiv'), (9771216, 'bl loc.imp.objc_msgSend'), (9771300, 'bl 0x951ef0'), (9771524, 'blx r2'), (9771628, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9771728, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9771756, 'bl sym.tileIsSolid_Tile_'), (9771880, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9771908, 'bl sym.tileIsSolid_Tile_'), (9772032, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9772060, 'bl sym.tileIsSolid_Tile_'), (9772184, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9772212, 'bl sym.tileIsSolid_Tile_'), (9772320, 'blx r2'), (9772560, 'bl loc.imp.objc_msgSend'), (9772600, 'blx ip')],
        branches=[(9769968, 'bne', 9772700), (9770208, 'beq', 9772696), (9770280, 'bne', 9770776), (9770320, 'bne', 9770776), (9770420, 'beq', 9770772), (9770496, 'bne', 9770768), (9770532, 'bne', 9770768), (9770768, 'b', 9772700), (9770772, 'b', 9770776), (9770900, 'blt', 9771016), (9771012, 'b', 9771296), (9771132, 'bge', 9771248), (9771244, 'b', 9771288), (9771308, 'bge', 9772632), (9771348, 'bne', 9771392), (9771388, 'bge', 9771480), (9771432, 'blt', 9772632), (9771476, 'bgt', 9772632), (9771552, 'bne', 9772628), (9771648, 'bne', 9772624), (9771748, 'beq', 9772620), (9771768, 'bne', 9772620), (9771784, 'beq', 9772620), (9771800, 'beq', 9772620), (9771900, 'beq', 9772616), (9771920, 'bne', 9772616), (9771936, 'beq', 9772616), (9771952, 'beq', 9772616), (9772052, 'beq', 9772612), (9772072, 'bne', 9772612), (9772088, 'beq', 9772612), (9772104, 'beq', 9772612), (9772204, 'beq', 9772608), (9772224, 'bne', 9772608), (9772240, 'beq', 9772608), (9772256, 'beq', 9772608), (9772332, 'bne', 9772604), (9772368, 'bne', 9772604), (9772604, 'b', 9772700), (9772608, 'b', 9772612), (9772612, 'b', 9772616), (9772616, 'b', 9772620), (9772620, 'b', 9772624), (9772624, 'b', 9772628), (9772628, 'b', 9772632), (9772632, 'b', 9772636), (9772692, 'b', 9770056), (9772696, 'b', 9772700)],
    ),
    dict(
        name='w_rmmacro',
        method='Wire -[removeFromMacroBlock]',
        types='v8@0:4',
        start=9783852,
        end=9784116,
        disasm='disasm_wire_removefrommacroblock.txt',
        base_add=9783868,
        base_literal=9784112,
        boundary='body trimmed to next IMP [occupiesForegroundContents] 0x00954b34 (exidx over-covered 0x00954c74)',
        selectors={9784088: (15219312, 'removeFromMacroBlock'), 9784108: (15219192, 'macroTiles')},
        imports={9784084: (17151900, 'objc_msgSendSuper2')},
        ivars={9784096: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 9784104: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={9784092: (15252928, 'OBJC_CLASS_$_Wire')},
        instructions=[(9783852, 'push {fp, lr}'), (9783960, 'bl loc.imp.objc_msgSend'), (9784004, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (9784072, 'blx r3'), (9784080, 'pop {fp, pc}')],
        semantics=("Teardown: reads the pos pair + 'macroTiles' msgSend + reloadDrawBlockDynamicObjectStaticGeometryForTile(posPair, macroTiles, world); then objc_msgSendSuper2(super, 'removeFromMacroBlock')."),
        calls=[(9783960, 'bl loc.imp.objc_msgSend'), (9784004, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (9784072, 'blx r3')],
        branches=[],
    ),
    dict(
        name='w_occfg',
        method='Wire -[occupiesForegroundContents]',
        types='c8@0:4',
        start=9784116,
        end=9784276,
        disasm='disasm_wire_occupiesforegroundcontents.txt',
        base_add=9784132,
        base_literal=9784272,
        boundary='consecutive IMPs: [occupiesNormalContents] follows at 0x00954bd4',
        selectors={},
        imports={},
        ivars={9784264: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 9784268: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16)},
        classes={},
        instructions=[(9784116, 'push {fp, lr}'), (9784220, 'ldrb r0, [r0, 0xb]'), (9784224, 'cmp r0, 0x60'), (9784260, 'pop {fp, pc}')],
        semantics=('tile = tileAtWorldPositionLoaded(pos.x, pos.y, world); return tile[0xb] == 0x60 (foreground contents occupied by the wire block id).'),
        calls=[(9784208, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(9784228, 'bne', 9784244), (9784240, 'b', 9784252)],
    ),
    dict(
        name='w_occnormal',
        method='Wire -[occupiesNormalContents]',
        types='c8@0:4',
        start=9784276,
        end=9784436,
        disasm='disasm_wire_occupiesnormalcontents.txt',
        base_add=9784292,
        base_literal=9784432,
        boundary='ARM.exidx bound 0x00954c74 (next class Plant at 0x00954f40)',
        selectors={},
        imports={},
        ivars={9784424: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 9784428: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16)},
        classes={},
        instructions=[(9784276, 'push {fp, lr}'), (9784380, 'ldrb r0, [r0, 3]'), (9784384, 'cmp r0, 0x60'), (9784420, 'pop {fp, pc}')],
        semantics=('tile = tileAtWorldPositionLoaded(pos.x, pos.y, world); return tile[3] == 0x60 (normal contents occupied by the wire block id).'),
        calls=[(9784368, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(9784388, 'bne', 9784404), (9784400, 'b', 9784412)],
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
        'batch': 'Wire class closure (non-render): init/save/net pairs, remoteUpdate, dealloc, getSaveDict, sub-derived reload, freeblock creation constants, worldChanged adjacency refresh, occupancy predicates (18 bodies)',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'wire_closure.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale wire_closure.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
