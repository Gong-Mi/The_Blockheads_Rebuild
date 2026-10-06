#!/usr/bin/env python3
"""Hash-gated recovery of the ElevatorMotor closure.

26 bodies, 2569 instruction words total, from the pinned original libApplication.so (1.7.6, armeabi-v7a):
init trio pair 1 (atPosition: 303w / saveDict: 218w / netData: 217w), getSaveDict 223w, dealloc 49w,
updateNetDataForClient: 21w, creationNetDataForClient: 223w, remoteUpdate: 178w, update:accurateDT:isSimulation: 159w,
draw 138w, worldChanged: 396w, minY/maxY/setMinY:/setMaxY: atomic accessors (15/15/17/17w), addDrawCubeData: 195w,
staticGeometryDrawCubeCount 8w, removeFromMacroBlock 66w, freeblock quartet, isStorageDevice 7w,
occupiesNormalContents 7w, initSubDerivedItems 42w, objectType 7w.
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
    'bl 0x700b38': 0X00700B38,
    'bl 0x70136c': 0X0070136C,
    'bl 0x702660': 0X00702660,
    'bl loc.imp.objc_msgSend': 0X001C281C,
    'bl loc.imp.objc_msgSendSuper2': 0X001C29FC,
    'bl loc.imp.objc_msgSend_stret': 0X001C2918,
    'bl sym.imp.memcpy': 0X001C2894,
    'bl sym.imp.memset': 0X001C2924,
    'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_': 0X00A19598,
    'bl sym.texCoordsForImageIndex_int_': 0X004D6820,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0X00A12F24,
}

SPECS = [
    dict(
        name='m_subderived',
        method='ElevatorMotor -[initSubDerivedItems]',
        types='v8@0:4',
        start=7339756,
        end=7339924,
        disasm='disasm_elevatormotor_initsubderiveditems.txt',
        base_add=7339788,
        base_literal=7339912,
        boundary='consecutive IMPs: [objectType] follows at 0x006fff94',
        selectors={7339920: (15205452, 'macroTiles')},
        imports={},
        ivars={7339908: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 7339916: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={},
        instructions=[(7339756, 'push {fp, lr}'), (7339852, 'bl loc.imp.objc_msgSend'), (7339904, 'pop {fp, pc}')],
        semantics=('initSubDerivedItems: builds the position intpair from DynamicObject.pos and calls reloadDrawBlockDynamicObjectStaticGeometryForTile(intpair, MacroTile*, World*) - the elevator motor draws through the static-geometry system.'),
        calls=[(7339852, 'bl loc.imp.objc_msgSend'), (7339896, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_')],
        branches=[],
    ),
    dict(
        name='m_objtype',
        method='ElevatorMotor -[objectType]',
        types='i8@0:4',
        start=7339924,
        end=7339952,
        disasm='disasm_elevatormotor_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [initWithWorld:dynamicWorld:atPosition:...] follows at 0x006fffb0',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7339924, 'sub sp, sp, 8'), (7339948, 'bx lr')],
        semantics=('objectType = 0x37 (55).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_initpos',
        method='ElevatorMotor -[initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:]',
        types='@40@0:4@8@12{?=ii}16@24i28@32@36',
        start=7339952,
        end=7341164,
        disasm='disasm_elevatormotor_initwithworld_position.txt',
        base_add=7339968,
        base_literal=7341160,
        boundary='consecutive IMPs: [initWithWorld:dynamicWorld:saveDict:cache:] follows at 0x0070046c',
        selectors={7341112: (15205456, 'initWithWorld:dynamicWorld:atPosition:cache:'), 7341144: (15205464, 'objectForKey:'), 7341152: (15205460, 'retain'), 7341156: (15205468, 'initSubDerivedItems')},
        imports={7341140: (17151904, 'objc_msgSend')},
        ivars={7341116: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 7341120: (17158916, 'OBJC_IVAR_$_ElevatorMotor.maxY', 68), 7341124: (17158920, 'OBJC_IVAR_$_ElevatorMotor.minY', 64), 7341128: (17158924, 'OBJC_IVAR_$_ElevatorMotor.itemType', 56), 7341132: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 7341148: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36)},
        classes={7341104: (15252712, 'OBJC_CLASS_$_ElevatorMotor')},
        instructions=[(7339952, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7340152, 'bl loc.imp.objc_msgSendSuper2'), (7341100, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Full placement: objc_msgSendSuper2 init + nil guard; stores level from the placedByClient/type args; scans UP from the start position while tileAtWorldPositionLoaded(x, i, world) has tile[3] == 0x67 (elevator-rail tile), storing the last rail Y as maxY; scans DOWN the same way for minY; a nil saveDict branch restores the extra field via [saveDict objectForKey:] + intValue; tail setup chain; return self.'),
        calls=[(7340152, 'bl loc.imp.objc_msgSendSuper2'), (7340428, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7340644, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7340808, 'blx r2'), (7340896, 'blx r3'), (7340996, 'blx lr'), (7341012, 'blx r2'), (7341080, 'blx r2')],
        branches=[(7340180, 'bne', 7340196), (7340192, 'b', 7341092), (7340356, 'bge', 7340528), (7340448, 'beq', 7340504), (7340464, 'bne', 7340504), (7340500, 'b', 7340508), (7340504, 'b', 7340528), (7340508, 'b', 7340512), (7340524, 'b', 7340348), (7340572, 'blt', 7340748), (7340664, 'beq', 7340720), (7340680, 'bne', 7340720), (7340716, 'b', 7340724), (7340720, 'b', 7340748), (7340724, 'b', 7340728), (7340744, 'b', 7340564), (7340760, 'beq', 7340836), (7340832, 'b', 7341040), (7340908, 'beq', 7341036), (7341036, 'b', 7341040)],
    ),
    dict(
        name='m_initsave',
        method='ElevatorMotor -[initWithWorld:dynamicWorld:saveDict:cache:]',
        types='@24@0:4@8@12@16@20',
        start=7341164,
        end=7342036,
        disasm='disasm_elevatormotor_initwithworld_savedict.txt',
        base_add=7341180,
        base_literal=7342032,
        boundary='consecutive IMPs: [initWithWorld:dynamicWorld:cache:netData:] follows at 0x007007d4',
        selectors={7341960: (15205472, 'initWithWorld:dynamicWorld:saveDict:cache:'), 7341972: (15205468, 'initSubDerivedItems'), 7341980: (15205460, 'retain'), 7341988: (15205464, 'objectForKey:'), 7341996: (15205480, 'unsignedIntValue'), 7342024: (15205476, 'intValue')},
        imports={7341956: (17151900, 'objc_msgSendSuper2'), 7341968: (17151904, 'objc_msgSend')},
        ivars={7341976: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 7341992: (17158916, 'OBJC_IVAR_$_ElevatorMotor.maxY', 68), 7342004: (17158920, 'OBJC_IVAR_$_ElevatorMotor.minY', 64), 7342012: (17158928, 'OBJC_IVAR_$_ElevatorMotor.availableElectricity', 60), 7342020: (17158924, 'OBJC_IVAR_$_ElevatorMotor.itemType', 56)},
        classes={7341964: (15252712, 'OBJC_CLASS_$_ElevatorMotor')},
        instructions=[(7341164, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7341316, 'blx r6'), (7341952, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Save-dict restore: objc_msgSendSuper2 init + nil guard; six fields decoded from the save dict via [saveDict objectForKey:<key>] + intValue (one stored as strh - the u16 field - the rest as str), the object ref fetched via retain; tail call; return self.'),
        calls=[(7341316, 'blx r6'), (7341636, 'blx r6'), (7341652, 'blx r2'), (7341696, 'blx r3'), (7341712, 'blx r2'), (7341756, 'blx r3'), (7341772, 'blx r2'), (7341816, 'blx r3'), (7341832, 'blx r2'), (7341876, 'blx r3'), (7341892, 'blx r2'), (7341932, 'blx r3')],
        branches=[(7341344, 'bne', 7341360), (7341356, 'b', 7341944)],
    ),
    dict(
        name='m_initnet',
        method='ElevatorMotor -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=7342036,
        end=7342904,
        disasm='disasm_elevatormotor_initwithworld_netdata.txt',
        base_add=7342052,
        base_literal=7342900,
        boundary='ARM.exidx end 0x00700b38; tail gap before [getSaveDict] at 0x00700b5c',
        selectors={7342832: (15205484, 'initWithWorld:dynamicWorld:cache:netData:'), 7342844: (15205492, 'length'), 7342864: (15205488, 'getBytes:length:'), 7342872: (15205460, 'retain'), 7342880: (15205464, 'objectForKey:'), 7342884: (15205500, 'gzipInflate'), 7342892: (15205496, 'subdataWithRange:'), 7342896: (15205468, 'initSubDerivedItems')},
        imports={7342828: (17151900, 'objc_msgSendSuper2'), 7342840: (17151904, 'objc_msgSend')},
        ivars={7342848: (17158916, 'OBJC_IVAR_$_ElevatorMotor.maxY', 68), 7342852: (17158920, 'OBJC_IVAR_$_ElevatorMotor.minY', 64), 7342856: (17158928, 'OBJC_IVAR_$_ElevatorMotor.availableElectricity', 60), 7342860: (17158924, 'OBJC_IVAR_$_ElevatorMotor.itemType', 56), 7342868: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36)},
        classes={7342836: (15252712, 'OBJC_CLASS_$_ElevatorMotor')},
        instructions=[(7342036, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7342188, 'blx r6'), (7342824, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Network restore: objc_msgSendSuper2 init + nil guard; getBytes into a 0x28-byte stack buffer; four uint16 fields read from the payload (offsets via the ivar slots: maxY/minY/...; two stored as strh + two as str); helper 0x700b38 (post-init chain); tail message chain (sel 0xffe20960); return self.'),
        calls=[(7342188, 'blx r6'), (7342356, 'blx r6'), (7342472, 'blx r4'), (7342544, 'bl loc.imp.objc_msgSend'), (7342612, 'bl loc.imp.objc_msgSend'), (7342636, 'blx r2'), (7342640, 'bl 0x700b38'), (7342724, 'blx r3'), (7342740, 'blx r2'), (7342804, 'blx r2')],
        branches=[(7342216, 'bne', 7342232), (7342228, 'b', 7342816), (7342480, 'bls', 7342764)],
    ),
    dict(
        name='m_getsave',
        method='ElevatorMotor -[getSaveDict]',
        types='@8@0:4',
        start=7342940,
        end=7343832,
        disasm='disasm_elevatormotor_getsavedict_closure.txt',
        base_add=7342956,
        base_literal=7343828,
        boundary='consecutive IMPs: [dealloc] follows at 0x00700ed8',
        selectors={7343760: (15205504, 'getSaveDict'), 7343780: (15205512, 'setObject:forKey:'), 7343784: (15205516, 'numberWithUnsignedInt:'), 7343816: (15205508, 'numberWithInt:')},
        imports={7343756: (17151900, 'objc_msgSendSuper2'), 7343776: (17151904, 'objc_msgSend')},
        ivars={7343768: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 7343788: (17158916, 'OBJC_IVAR_$_ElevatorMotor.maxY', 68), 7343800: (17158920, 'OBJC_IVAR_$_ElevatorMotor.minY', 64), 7343808: (17158928, 'OBJC_IVAR_$_ElevatorMotor.availableElectricity', 60), 7343820: (17158924, 'OBJC_IVAR_$_ElevatorMotor.itemType', 56)},
        classes={7343764: (15252712, 'OBJC_CLASS_$_ElevatorMotor')},
        instructions=[(7342940, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7343024, 'blx ip'), (7343752, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('getSaveDict: super stret dict; then per-field [dict setObject:[NSNumber numberWithInt:[self field]] forKey:<CFString key>] pairs (one ldrh field via numberWithInt, minY/maxY as str loads, + a conditional key when two fields differ); CFString keys 0xfff273xx (v2-era keys, not resolvable in this build).'),
        calls=[(7343024, 'blx ip'), (7343296, 'blx ip'), (7343332, 'blx ip'), (7343392, 'blx r3'), (7343428, 'blx ip'), (7343488, 'blx r3'), (7343524, 'blx ip'), (7343584, 'blx r3'), (7343620, 'blx ip'), (7343740, 'blx ip')],
        branches=[(7343652, 'beq', 7343744)],
    ),
    dict(
        name='m_dealloc',
        method='ElevatorMotor -[dealloc]',
        types='v8@0:4',
        start=7343832,
        end=7344028,
        disasm='disasm_elevatormotor_dealloc.txt',
        base_add=7343848,
        base_literal=7344024,
        boundary='consecutive IMPs: [updateNetDataForClient:] follows at 0x00700f9c',
        selectors={7344004: (15205524, 'dealloc'), 7344016: (15205520, 'release')},
        imports={7344000: (17151900, 'objc_msgSendSuper2'), 7344012: (17151904, 'objc_msgSend')},
        ivars={7344020: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36)},
        classes={7344008: (15252712, 'OBJC_CLASS_$_ElevatorMotor')},
        instructions=[(7343832, 'push {r4, r5, r6, r7, fp, lr}'), (7343948, 'blx r5'), (7343996, 'pop {r4, r5, r6, r7, fp, pc}')],
        semantics=('Teardown: release the retained ivar object; objc_msgSendSuper2(super, dealloc).'),
        calls=[(7343948, 'blx r5'), (7343988, 'blx r2')],
        branches=[],
    ),
    dict(
        name='m_updnet',
        method='ElevatorMotor -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=7344028,
        end=7344112,
        disasm='disasm_elevatormotor_updatenetdata.txt',
        base_add=7344044,
        base_literal=7344108,
        boundary='consecutive IMPs: [creationNetDataForClient:] follows at 0x00700ff0',
        selectors={7344104: (15205528, 'creationNetDataForClient:')},
        imports={7344100: (17151904, 'objc_msgSend')},
        ivars={},
        classes={},
        instructions=[(7344028, 'push {fp, lr}'), (7344088, 'blx ip'), (7344096, 'pop {fp, pc}')],
        semantics=('updateNetDataForClient: single forward: [self <sel 0xffe209a4> arg] (the scheduler hook); no local state.'),
        calls=[(7344088, 'blx ip')],
        branches=[],
    ),
    dict(
        name='m_creationnet',
        method='ElevatorMotor -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=7344112,
        end=7345004,
        disasm='disasm_elevatormotor_creationnetdata.txt',
        base_add=7344128,
        base_literal=7345000,
        boundary='ARM.exidx end 0x0070136c; tail gap before [remoteUpdate:] at 0x007014d8',
        selectors={7344936: (15205532, 'dynamicObjectNetData'), 7344948: (15205540, 'dictionary'), 7344956: (15205536, 'dataWithBytes:length:'), 7344988: (15205512, 'setObject:forKey:'), 7344992: (15205548, 'appendData:'), 7344996: (15205544, 'gzipDeflate')},
        imports={7344944: (17151904, 'objc_msgSend')},
        ivars={7344940: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 7344964: (17158932, 'OBJC_IVAR_$_ElevatorMotor.clientPowerUsage', 62), 7344968: (17158916, 'OBJC_IVAR_$_ElevatorMotor.maxY', 68), 7344972: (17158920, 'OBJC_IVAR_$_ElevatorMotor.minY', 64), 7344976: (17158928, 'OBJC_IVAR_$_ElevatorMotor.availableElectricity', 60), 7344980: (17158924, 'OBJC_IVAR_$_ElevatorMotor.itemType', 56)},
        classes={},
        instructions=[(7344112, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7344204, 'bl loc.imp.objc_msgSend_stret'), (7344932, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('creationNetDataForClient: super stret 0x18-byte net struct (or memset 0 when nil client); then fills a 0x18-byte payload from the object (12 words of the six u16 fields + level), memcpy assembles the frame, [X appendData:...] pair, helper 0x70136c (gzip region), one conditional tail key; returns the assembled data object.'),
        calls=[(7344204, 'bl loc.imp.objc_msgSend_stret'), (7344240, 'bl sym.imp.memset'), (7344484, 'bl sym.imp.memcpy'), (7344664, 'blx r5'), (7344700, 'blx r3'), (7344824, 'blx ip'), (7344832, 'bl 0x70136c'), (7344892, 'blx lr'), (7344920, 'blx r3')],
        branches=[(7344188, 'beq', 7344212), (7344208, 'b', 7344244), (7344736, 'beq', 7344828)],
    ),
    dict(
        name='m_remoteupd',
        method='ElevatorMotor -[remoteUpdate:]',
        types='v12@0:4@8',
        start=7345368,
        end=7346080,
        disasm='disasm_elevatormotor_remoteupdate.txt',
        base_add=7345384,
        base_literal=7346076,
        boundary='consecutive IMPs: [update:accurateDT:isSimulation:] follows at 0x007017a0',
        selectors={7346016: (15205552, 'remoteUpdate:'), 7346032: (15205488, 'getBytes:length:'), 7346048: (15205556, 'objectType'), 7346052: (15205560, 'dynamicWorldChangedAtPos:objectType:')},
        imports={7346012: (17151900, 'objc_msgSendSuper2'), 7346028: (17151904, 'objc_msgSend')},
        ivars={7346024: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52), 7346036: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 7346044: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 7346056: (17158928, 'OBJC_IVAR_$_ElevatorMotor.availableElectricity', 60), 7346064: (17158936, 'OBJC_IVAR_$_ElevatorMotor.timeUntilNextPowerCheck', 72), 7346068: (17158916, 'OBJC_IVAR_$_ElevatorMotor.maxY', 68), 7346072: (17158920, 'OBJC_IVAR_$_ElevatorMotor.minY', 64)},
        classes={7346020: (15252712, 'OBJC_CLASS_$_ElevatorMotor')},
        instructions=[(7345368, 'push {r4, r5, r6, r7, fp, lr}'), (7345460, 'blx lr'), (7346008, 'pop {r4, r5, r6, r7, fp, pc}')],
        semantics=('remoteUpdate: objc_msgSendSuper2(super, remoteUpdate:) + getBytes:length: decode (u16 fields incl. availableElectricity / minY / maxY); if !isNet: clear timeUntilNextPowerCheck to 0.0f when availableElectricity > 0 and packet field > 0; else decrement availableElectricity by the packet value (strh, clamped at 0); if isNet: write availableElectricity/minY/maxY from the packet + [dynamicWorldChangedAtPos:objectType:] replay.'),
        calls=[(7345460, 'blx lr'), (7345600, 'bl loc.imp.objc_msgSend'), (7345636, 'bl loc.imp.objc_msgSend'), (7345676, 'blx ip')],
        branches=[(7345704, 'bne', 7345916), (7345740, 'ble', 7345796), (7345752, 'ble', 7345796), (7345832, 'ble', 7345880), (7345876, 'b', 7345912), (7345912, 'b', 7346004)],
    ),
    dict(
        name='m_update',
        method='ElevatorMotor -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=7346080,
        end=7346716,
        disasm='disasm_elevatormotor_update.txt',
        base_add=7346096,
        base_literal=7346712,
        boundary='consecutive IMPs: [draw:...] follows at 0x00701a1c',
        selectors={7346684: (15205564, 'findAndSubtractAllPowerUpTo:forUser:'), 7346704: (15205556, 'objectType'), 7346708: (15205560, 'dynamicWorldChangedAtPos:objectType:')},
        imports={7346680: (17151904, 'objc_msgSend')},
        ivars={7346668: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52), 7346672: (17158928, 'OBJC_IVAR_$_ElevatorMotor.availableElectricity', 60), 7346676: (17158936, 'OBJC_IVAR_$_ElevatorMotor.timeUntilNextPowerCheck', 72), 7346688: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 7346692: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49), 7346700: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16)},
        classes={},
        instructions=[(7346080, 'push {r4, r5, r6, sl, fp, lr}'), (7346420, 'blx ip'), (7346664, 'pop {r4, r5, r6, sl, fp, pc}')],
        semantics=('update:accurateDT:isSimulation: power tick - if !isNet and availableElectricity (u16@60) < 0xf: timeUntilNextPowerCheck (float@72) -= accurateDT; when <= 0 reset to 5.0f; pending = 0xf - availableElectricity; [dynamicWorld findAndSubtractAllPowerUpTo:pending forUser:0] - if result > 0: availableElectricity += result (strh); [self objectType] / [dynamicWorld dynamicWorldChangedAtPos:objectType:]; updateNeedsToBeSent = 1.'),
        calls=[(7346420, 'blx ip'), (7346584, 'bl loc.imp.objc_msgSend'), (7346620, 'bl loc.imp.objc_msgSend')],
        branches=[(7346164, 'bne', 7346660), (7346200, 'bge', 7346656), (7346268, 'bhi', 7346652), (7346436, 'ble', 7346648), (7346648, 'b', 7346652), (7346652, 'b', 7346656), (7346656, 'b', 7346660)],
    ),
    dict(
        name='m_draw',
        method='ElevatorMotor -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=7346716,
        end=7347268,
        disasm='disasm_elevatormotor_draw.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [freeblockCreationItemType] follows at 0x00701c44',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7346716, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7347264, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('draw:... arg-frame reshuffle shim (26 argument words moved to the callee frame; 0 calls / 0 branches - the GL submission is outside this body).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_fbitem',
        method='ElevatorMotor -[freeblockCreationItemType]',
        types='i8@0:4',
        start=7347268,
        end=7347328,
        disasm='disasm_elevatormotor_freeblockcreationitemtype.txt',
        base_add=7347276,
        base_literal=7347324,
        boundary='consecutive IMPs: [freeBlockCreationSaveDict] follows at 0x00701c80',
        selectors={},
        imports={},
        ivars={7347320: (17158924, 'OBJC_IVAR_$_ElevatorMotor.itemType', 56)},
        classes={},
        instructions=[(7347268, 'sub sp, sp, 8'), (7347316, 'bx lr')],
        semantics=('freeblockCreationItemType = ivar load (the freeblock item id for placement).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_fbsave',
        method='ElevatorMotor -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=7347328,
        end=7347404,
        disasm='disasm_elevatormotor_freeblockcreationsavedict.txt',
        base_add=7347344,
        base_literal=7347400,
        boundary='consecutive IMPs: [freeBlockCreationDataA] follows at 0x00701ccc',
        selectors={7347396: (15205504, 'getSaveDict')},
        imports={7347392: (17151904, 'objc_msgSend')},
        ivars={},
        classes={},
        instructions=[(7347328, 'push {fp, lr}'), (7347380, 'blx r3'), (7347388, 'pop {fp, pc}')],
        semantics=('freeBlockCreationSaveDict = single forward ([super-level sel 0xffe2098c]).'),
        calls=[(7347380, 'blx r3')],
        branches=[],
    ),
    dict(
        name='m_fba',
        method='ElevatorMotor -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=7347404,
        end=7347432,
        disasm='disasm_elevatormotor_freeblockcreationdataa.txt',
        base_add=None,
        base_literal=None,
        boundary='body trimmed at the next IMP 0x00701ce8 (ARM.exidx over-covers into the following method)',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7347404, 'sub sp, sp, 8'), (7347428, 'bx lr')],
        semantics=('freeBlockCreationDataA = 0 (uxth).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_fbb',
        method='ElevatorMotor -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=7347432,
        end=7347460,
        disasm='disasm_elevatormotor_freeblockcreationdatab.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [worldChanged:] follows at 0x00701d04',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7347432, 'sub sp, sp, 8'), (7347456, 'bx lr')],
        semantics=('freeBlockCreationDataB = 0 (uxth).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_worldchanged',
        method='ElevatorMotor -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=7347460,
        end=7349044,
        disasm='disasm_elevatormotor_worldchanged.txt',
        base_add=7347476,
        base_literal=7349040,
        boundary='consecutive IMPs: [staticGeometryDrawCubeCount] follows at 0x00702334',
        selectors={},
        imports={},
        ivars={7349016: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52), 7349020: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 7349024: (17158920, 'OBJC_IVAR_$_ElevatorMotor.minY', 64), 7349028: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 7349032: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49), 7349036: (17158916, 'OBJC_IVAR_$_ElevatorMotor.maxY', 68)},
        classes={},
        instructions=[(7347460, 'push {fp, lr}'), (7347972, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7349012, 'pop {fp, pc}')],
        semantics=('worldChanged: for each changed intpair (external bounding iteration, 8-byte steps): gate isNet; if change.x == pos.x: if change.y > maxY and y == maxY+1: re-scan UP from maxY+1 to 0x400 while tiles keep tile[3] == 0x67, extending maxY; if the changed tile inside [minY..maxY] loses its rail: maxY = y-1 (shrink, updateNeedsToBeSent = 1). Symmetric for minY (down scan / minY = y+1 on shrink).'),
        calls=[(7347972, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7348248, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7348516, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7348792, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(7347524, 'beq', 7347532), (7347528, 'b', 7349008), (7347768, 'beq', 7349008), (7347840, 'bne', 7348944), (7347880, 'ble', 7348388), (7347920, 'bgt', 7348080), (7347992, 'beq', 7348076), (7348008, 'beq', 7348076), (7348076, 'b', 7348384), (7348120, 'bne', 7348380), (7348176, 'bge', 7348376), (7348268, 'beq', 7348352), (7348284, 'bne', 7348352), (7348348, 'b', 7348356), (7348352, 'b', 7348376), (7348356, 'b', 7348360), (7348372, 'b', 7348168), (7348376, 'b', 7348380), (7348380, 'b', 7348384), (7348384, 'b', 7348940), (7348424, 'bge', 7348936), (7348464, 'blt', 7348624), (7348536, 'beq', 7348620), (7348552, 'beq', 7348620), (7348620, 'b', 7348932), (7348664, 'bne', 7348928), (7348720, 'blt', 7348924), (7348812, 'beq', 7348896), (7348828, 'bne', 7348896), (7348892, 'b', 7348900), (7348896, 'b', 7348924), (7348900, 'b', 7348904), (7348920, 'b', 7348712), (7348924, 'b', 7348928), (7348928, 'b', 7348932), (7348932, 'b', 7348936), (7348936, 'b', 7348940), (7348940, 'b', 7348944), (7348944, 'b', 7348948), (7349004, 'b', 7347616)],
    ),
    dict(
        name='m_sgcdc',
        method='ElevatorMotor -[staticGeometryDrawCubeCount]',
        types='i8@0:4',
        start=7349044,
        end=7349076,
        disasm='disasm_elevatormotor_staticgeometrydrawcubecount.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [addDrawCubeData:fromIndex:] follows at 0x00702354',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7349044, 'sub sp, sp, 0xc'), (7349072, 'bx lr')],
        semantics=('staticGeometryDrawCubeCount = 1 (single cube).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_addcube',
        method='ElevatorMotor -[addDrawCubeData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=7349076,
        end=7349856,
        disasm='disasm_elevatormotor_adddrawcubedata.txt',
        base_add=7349128,
        base_literal=7349840,
        boundary='ARM.exidx end 0x00702660; tail gap before [removeFromMacroBlock] at 0x007026d4',
        selectors={7349852: (15205568, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:')},
        imports={},
        ivars={7349836: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 7349848: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12)},
        classes={7349844: (15246504, 'OBJC_CLASS_$_DrawCube')},
        instructions=[(7349076, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7349216, 'bl 0x702660'), (7349832, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('addDrawCubeData:fromIndex: DrawCube builder: floatPos (+5y) / z = -1.5f (0xbfc00000); calls helper 0x702660 (vertex fill); texCoordsForImageIndex(0x248) - texture 584; fills a 20-word vertex block (0.5f x3 + 1.0f x3 + ...); submits fillBuffer:...:matrix:... (20-arg, 0xe83a6c) via objc_msgSend; returns index+1.'),
        calls=[(7349216, 'bl 0x702660'), (7349228, 'bl sym.texCoordsForImageIndex_int_'), (7349808, 'bl loc.imp.objc_msgSend')],
        branches=[],
    ),
    dict(
        name='m_rmmacro',
        method='ElevatorMotor -[removeFromMacroBlock]',
        types='v8@0:4',
        start=7349972,
        end=7350236,
        disasm='disasm_elevatormotor_removefrommacroblock.txt',
        base_add=7349988,
        base_literal=7350232,
        boundary='consecutive IMPs: [isStorageDevice] follows at 0x007027dc',
        selectors={7350208: (15205572, 'removeFromMacroBlock'), 7350228: (15205452, 'macroTiles')},
        imports={7350204: (17151900, 'objc_msgSendSuper2')},
        ivars={7350216: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 7350224: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={7350212: (15252712, 'OBJC_CLASS_$_ElevatorMotor')},
        instructions=[(7349972, 'push {fp, lr}'), (7350080, 'bl loc.imp.objc_msgSend'), (7350200, 'pop {fp, pc}')],
        semantics=('removeFromMacroBlock: reloadDrawBlockDynamicObjectStaticGeometryForTile(intpair, macroTile, world) for the object position, then objc_msgSendSuper2(super, removeFromMacroBlock) - the static-geometry unregister + super teardown.'),
        calls=[(7350080, 'bl loc.imp.objc_msgSend'), (7350124, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (7350192, 'blx r3')],
        branches=[],
    ),
    dict(
        name='m_isstorage',
        method='ElevatorMotor -[isStorageDevice]',
        types='c8@0:4',
        start=7350236,
        end=7350264,
        disasm='disasm_elevatormotor_isstoragedevice.txt',
        base_add=None,
        base_literal=None,
        boundary='body trimmed at the next IMP 0x007027f8 (ARM.exidx over-covers into the following method)',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7350236, 'sub sp, sp, 8'), (7350260, 'bx lr')],
        semantics=('isStorageDevice = 0 (motor is not a storage device).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_occnormal',
        method='ElevatorMotor -[occupiesNormalContents]',
        types='c8@0:4',
        start=7350696,
        end=7350724,
        disasm='disasm_elevatormotor_occupiesnormalcontents.txt',
        base_add=None,
        base_literal=None,
        boundary='body trimmed at the next IMP 0x007029c4 (ARM.exidx over-covers into the following method)',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7350696, 'sub sp, sp, 8'), (7350720, 'bx lr')],
        semantics=('occupiesNormalContents = 1.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_miny',
        method='ElevatorMotor -[minY]',
        types='i8@0:4',
        start=7350724,
        end=7350784,
        disasm='disasm_elevatormotor_miny.txt',
        base_add=7350748,
        base_literal=7350780,
        boundary='consecutive IMPs: [setMinY:] follows at 0x00702a00',
        selectors={},
        imports={},
        ivars={7350776: (17158920, 'OBJC_IVAR_$_ElevatorMotor.minY', 64)},
        classes={},
        instructions=[(7350724, 'sub sp, sp, 8'), (7350772, 'bx lr')],
        semantics=('minY = atomic (dmb ish) 32-bit load of ElevatorMotor.minY@64.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_setminy',
        method='ElevatorMotor -[setMinY:]',
        types='v12@0:4i8',
        start=7350784,
        end=7350852,
        disasm='disasm_elevatormotor_setminy.txt',
        base_add=7350812,
        base_literal=7350848,
        boundary='consecutive IMPs: [maxY] follows at 0x00702a44',
        selectors={},
        imports={},
        ivars={7350844: (17158920, 'OBJC_IVAR_$_ElevatorMotor.minY', 64)},
        classes={},
        instructions=[(7350784, 'sub sp, sp, 0xc'), (7350840, 'bx lr')],
        semantics=('setMinY: = dmb ish-flagged atomic 32-bit store to ElevatorMotor.minY@64.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_maxy',
        method='ElevatorMotor -[maxY]',
        types='i8@0:4',
        start=7350852,
        end=7350912,
        disasm='disasm_elevatormotor_maxy.txt',
        base_add=7350876,
        base_literal=7350908,
        boundary='consecutive IMPs: [setMaxY:] follows at 0x00702a80',
        selectors={},
        imports={},
        ivars={7350904: (17158916, 'OBJC_IVAR_$_ElevatorMotor.maxY', 68)},
        classes={},
        instructions=[(7350852, 'sub sp, sp, 8'), (7350900, 'bx lr')],
        semantics=('maxY = atomic (dmb ish) 32-bit load of ElevatorMotor.maxY@68.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='m_setmaxy',
        method='ElevatorMotor -[setMaxY:]',
        types='v12@0:4i8',
        start=7350912,
        end=7350980,
        disasm='disasm_elevatormotor_setmaxy.txt',
        base_add=7350940,
        base_literal=7350976,
        boundary='ARM.exidx end 0x00702ac4; tail gap before [class tail 0x00702b3c] at 0x00702b3c',
        selectors={},
        imports={},
        ivars={7350972: (17158916, 'OBJC_IVAR_$_ElevatorMotor.maxY', 68)},
        classes={},
        instructions=[(7350912, 'sub sp, sp, 0xc'), (7350968, 'bx lr')],
        semantics=('setMaxY: = dmb ish-flagged atomic 32-bit store to ElevatorMotor.maxY@68.'),
        calls=[],
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
        'batch': 'ElevatorMotor closure: init/save/net trio pairs, update/getSaveDict/creationNetDataForClient/remoteUpdate, worldChanged rail re-scan, minY/maxY atomic accessors, static-geometry (sgcdc/addDrawCubeData/removeFromMacroBlock/draw), freeblock quartet, isStorageDevice/occupiesNormalContents/objectType=0x37 (26 bodies)',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'elevator_motor.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale elevator_motor.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
