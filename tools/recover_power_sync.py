#!/usr/bin/env python3
"""Hash-gated recovery of the electricity net-sync pair + wire forwarding helpers + WirePathCreator lifecycle.

8 bodies, 1912 instruction words total, from the pinned original libApplication.so (1.7.6, armeabi-v7a):
World sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient: (603w), World electricityPathDataRecieved:fromClient: (333w),
DynamicWorld initialDynamicObjectsNetDataForMacroTileIndex:wireForClient: (725w), DynamicWorld addWireAtPos:ofType:saveDict:placedByClient: (41w),
DynamicWorld wireAtPos: (28w), DynamicWorld removeWireAtPos: (45w), WirePathCreator initWithWorld: (61w), WirePathCreator dealloc (76w).
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
    'bl loc.imp.objc_msgSend': 0X001C281C,
    'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__': 0X005CB054,
    'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_': 0X005CAEF8,
    'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_': 0X005DB5B4,
    'bl sym.imp._Unwind_Resume': 0X001C29C0,
    'bl sym.imp.__aeabi_idiv': 0X001C3728,
    'bl sym.imp.__modsi3': 0X001C3020,
    'bl sym.imp.__wrap_free': 0X001C2E64,
    'bl sym.imp.__wrap_malloc': 0X001C2E58,
    'bl sym.imp.memset': 0X001C2924,
    'bl sym.imp.objc_enumerationMutation': 0X001C2E28,
    'bl sym.macroIndexAtWorldIndex_int__World_': 0X00A173C4,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0X00A12F24,
}

SPECS = [
    dict(
        name='world_sendelecpath',
        method='World -[sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient:]',
        types='v28@0:4{vector<ElectrictyParticlePathIndex, std::__1::allocator<ElectrictyParticlePathIndex> >=^{ElectrictyParticlePathIndex}^{ElectrictyParticlePathIndex}{__compressed_pair<ElectrictyParticlePathIndex *, std::__1::allocator<ElectrictyParticlePathIndex> >=^{ElectrictyParticlePathIndex}}}8f20@24',
        start=6070360,
        end=6072772,
        disasm='disasm_world_sendelectricitynetdata.txt',
        base_add=6070380,
        base_literal=6072768,
        boundary='ARM.exidx bound 0x005ca9c4 == next method IMP -[electricityPathDataRecieved:fromClient:]',
        selectors={6072688: (15195688, 'array'), 6072696: (15195620, 'countByEnumeratingWithState:objects:count:'), 6072704: (15196476, 'isEqualToString:'), 6072708: (15195672, 'connected'), 6072712: (15195624, 'objectForKey:'), 6072716: (15197492, 'blockIsWired:'), 6072720: (15195700, 'addObject:'), 6072724: (15195604, 'count'), 6072736: (15195552, 'dataWithBytes:length:'), 6072740: (15195632, 'appendBytes:length:'), 6072744: (15195612, 'appendData:'), 6072748: (15195608, 'gzipDeflate'), 6072760: (15195640, 'sendNetworkData:toPeers:reliable:'), 6072764: (15195644, 'sendDataToServer:reliable:')},
        imports={6072684: (17151904, 'objc_msgSend')},
        ivars={6072676: (17155972, 'OBJC_IVAR_$_World.client', 960), 6072680: (17155916, 'OBJC_IVAR_$_World.server', 964), 6072700: (17155964, 'OBJC_IVAR_$_World.serverClients', 956)},
        classes={},
        instructions=[(6070360, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6070540, 'cmp r0, 2'), (6070812, 'bl sym.imp.memset'), (6071724, 'mov r3, 0x2c'), (6071824, 'bl sym.imp.__wrap_malloc'), (6072660, 'bl sym.imp.__wrap_free'), (6072672, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Server/client broadcast of an electricity particle path. (vector<ElectrictyParticlePathIndex> paths, float size, BOOL ignoreClient). Gate 1: World.client@960 == nil && World.server@964 == nil -> return (standalone session, no net). Gate 2: (paths.end - paths.begin)/8 <= 2 -> return (needs more than 2 path entries). Serialized frame: 8-byte header at [sp,0xd0] (strh (int)size via vcvt.s32.f32; strh (end-begin)>>3 = path count), pushed through dataWithBytes:length: / appendBytes:length: (8) / appendData: with the packed {x,y}*count blob (__wrap_malloc(count<<3), 8-byte pair copy loop 0x5ca674..0x5ca788) and compressed via gzipDeflate. Recipients: World.serverClients@956 dictionary enumerated (countByEnumeratingWithState: guard), per-client state via isEqualToString:/connected, per-path macro screening via blockIsWired:/macroIndexAtWorldIndex + addObject:; server route ends in sendNetworkData:toPeers:reliable:, client route in sendDataToServer:reliable: (two final call sites keyed on the field compare at 0x5ca880). Blob freed via __wrap_free (0x5ca954).'),
        calls=[(6070536, 'bl sym.imp.__aeabi_idiv'), (6070612, 'blx r3'), (6070812, 'bl sym.imp.memset'), (6070876, 'blx lr'), (6070976, 'bl sym.imp.objc_enumerationMutation'), (6071056, 'blx ip'), (6071160, 'blx ip'), (6071184, 'blx r2'), (6071224, 'bl sym.macroIndexAtWorldIndex_int__World_'), (6071280, 'blx r3'), (6071320, 'bl sym.macroIndexAtWorldIndex_int__World_'), (6071376, 'blx r3'), (6071440, 'blx r3'), (6071548, 'blx ip'), (6071660, 'blx r2'), (6071780, 'bl loc.imp.objc_msgSend'), (6071808, 'bl loc.imp.objc_msgSend'), (6071824, 'bl sym.imp.__wrap_malloc'), (6072348, 'blx r6'), (6072388, 'blx r3'), (6072420, 'blx r3'), (6072544, 'blx ip'), (6072652, 'blx lr'), (6072660, 'bl sym.imp.__wrap_free')],
        branches=[(6070452, 'bne', 6070496), (6070492, 'beq', 6072668), (6070544, 'bls', 6072668), (6070648, 'beq', 6071580), (6070888, 'beq', 6071572), (6070968, 'beq', 6070980), (6071068, 'bne', 6071448), (6071196, 'beq', 6071444), (6071292, 'bne', 6071392), (6071388, 'beq', 6071444), (6071444, 'b', 6071448), (6071448, 'b', 6071452), (6071476, 'blo', 6070932), (6071568, 'bne', 6070932), (6071572, 'b', 6071576), (6071576, 'b', 6071580), (6071616, 'bne', 6071672), (6071668, 'bls', 6072664), (6072076, 'beq', 6072204), (6072200, 'b', 6071924), (6072452, 'beq', 6072552), (6072548, 'b', 6072656), (6072664, 'b', 6072668)],
    ),
    dict(
        name='world_elecpathrecv',
        method='World -[electricityPathDataRecieved:fromClient:]',
        types='v16@0:4@8@12',
        start=6072772,
        end=6074104,
        disasm='disasm_world_electricitypathrecv.txt',
        base_add=6072792,
        base_literal=6074100,
        boundary='ARM.exidx bound 0x005caef8 == vector<ElectrictyParticlePathIndex> dtor symbol region (own-bound 0x534 bytes)',
        selectors={6074048: (15196836, 'gzipInflate'), 6074052: (15195656, 'getBytes:length:'), 6074060: (15195652, 'length'), 6074064: (15196832, 'subdataWithRange:'), 6074076: (15195544, 'instance'), 6074080: (15198092, 'doAddElectricityParticleWithPath:size:'), 6074092: (15198096, 'sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient:')},
        imports={6074044: (17151904, 'objc_msgSend')},
        ivars={6074088: (17155916, 'OBJC_IVAR_$_World.server', 964)},
        classes={6074068: (15245388, 'OBJC_CLASS_$_ParticleEmitter')},
        instructions=[(6072772, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6072924, 'sub r0, r0, 8'), (6073112, 'bl sym.imp.__wrap_malloc'), (6073612, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'), (6074040, 'bl sym.imp._Unwind_Resume'), (6074032, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Inbound electricity particle path. (NSData data, BOOL fromClient). length == 8 -> return (header-only message). Else gzipInflate -> subdataWithRange: -> UInt16 count read from the buffer (ldrh; lsl <<3), __wrap_malloc(count<<3), getBytes:length: into it; a local vector<ElectrictyParticlePathIndex> is built by push_back (slow path bl 0x5db5b4) of each 8-byte {x,y} pair (loop 0x5cabc8..0x5cad2c); then [[ParticleEmitter instance] doAddElectricityParticleWithPath:(vector copy) size:(float)uint16] spawns the visual; when World.server@964 != nil the same vector + size is forwarded via [self sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient:] using fromClient as the ignore tag (loop prevention). Three ~vector unwind paths (0x5cadac..0x5caea8) + _Unwind_Resume (0x5caeb8).'),
        calls=[(6072896, 'bl loc.imp.objc_msgSend'), (6072920, 'bl loc.imp.objc_msgSend'), (6072988, 'bl loc.imp.objc_msgSend'), (6073004, 'blx r2'), (6073112, 'bl sym.imp.__wrap_malloc'), (6073164, 'blx lr'), (6073612, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'), (6073684, 'bl loc.imp.objc_msgSend'), (6073704, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'), (6073756, 'bl loc.imp.objc_msgSend'), (6073768, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (6073840, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'), (6073916, 'bl loc.imp.objc_msgSend'), (6073928, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (6073956, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (6073984, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (6074000, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (6074016, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (6074040, 'bl sym.imp._Unwind_Resume')],
        branches=[(6073024, 'beq', 6074028), (6073304, 'bge', 6073660), (6073392, 'beq', 6073604), (6073540, 'beq', 6073584), (6073600, 'b', 6073624), (6073616, 'b', 6073620), (6073620, 'b', 6073624), (6073624, 'b', 6073628), (6073628, 'b', 6073632), (6073644, 'b', 6073288), (6073656, 'b', 6074012), (6073692, 'b', 6073696), (6073708, 'b', 6073712), (6073760, 'b', 6073764), (6073812, 'beq', 6073996), (6073844, 'b', 6073848), (6073920, 'b', 6073924), (6073936, 'b', 6073996), (6073964, 'b', 6074012), (6073992, 'b', 6074012), (6074008, 'b', 6074028), (6074024, 'b', 6074036)],
    ),
    dict(
        name='dw_initialwirenets',
        method='DynamicWorld -[initialDynamicObjectsNetDataForMacroTileIndex:wireForClient:]',
        types='@16@0:4i8@12',
        start=9130752,
        end=9133652,
        disasm='disasm_dynamicworld_initialwirenets.txt',
        base_add=9130768,
        base_literal=9133648,
        boundary='ARM.exidx bound 0x008b5e54 == next IMP region',
        selectors={9133532: (15216132, 'loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:'), 9133548: (15215940, 'dictionary'), 9133552: (15215944, 'setObject:forKey:'), 9133564: (15216036, 'macroTiles'), 9133568: (15216128, 'worldWidthMacro'), 9133572: (15215864, 'count'), 9133576: (15215840, 'countByEnumeratingWithState:objects:count:'), 9133580: (15215884, 'objectForKey:'), 9133588: (15216140, 'isKindOfClass:'), 9133592: (15216136, 'class'), 9133600: (15216152, 'creationNetDataForClient:'), 9133604: (15216168, 'objectType'), 9133608: (15216148, 'numberWithUnsignedInt:'), 9133616: (15216144, 'array'), 9133624: (15216164, 'wireDynamicObject:'), 9133628: (15216008, 'addObject:'), 9133636: (15216160, 'uniqueID'), 9133640: (15216156, 'updateNetDataForClient:')},
        imports={9133528: (17151904, 'objc_msgSend')},
        ivars={9133536: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4), 9133584: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24)},
        classes={9133596: (15247828, 'OBJC_CLASS_$_Blockhead')},
        instructions=[(9130752, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9131136, 'bl sym.imp.__modsi3'), (9131208, 'bl sym.imp.__aeabi_idiv'), (9131272, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9131776, 'bl sym.imp.objc_enumerationMutation'), (9133524, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Initial wire-objects net data for one macro tile. (int macroTileIndex, BOOL wireForClient). Early gates: World refs nil / serverClients@24 count <= 0 -> return nil. loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks: on world@4; macro x/y derived via __modsi3 / __aeabi_idiv (worldWidthMacro) then <<5 world coords -> tileAtWorldPositionLoaded; per dynamic object: isKindOfClass: with OBJC_CLASS_$_Blockhead screens blockheads out; wires flow through wireDynamicObject: (variant chosen by wireForClient) into an NSMutableArray (array/addObject:); per-object net identity from objectType/uniqueID (numberWithUnsignedInt:) and payloads creationNetDataForClient: / updateNetDataForClient:; a macroTiles dictionary record is maintained (dictionary/setObject:forKey:); final wrap returns the assembled net data or nil (0x8b5d84..).'),
        calls=[(9130856, 'bl loc.imp.objc_msgSend'), (9130884, 'bl loc.imp.objc_msgSend'), (9130912, 'bl loc.imp.objc_msgSend'), (9130956, 'bl loc.imp.objc_msgSend'), (9130988, 'bl loc.imp.objc_msgSend'), (9131044, 'bl loc.imp.objc_msgSend'), (9131116, 'bl loc.imp.objc_msgSend'), (9131136, 'bl sym.imp.__modsi3'), (9131188, 'bl loc.imp.objc_msgSend'), (9131208, 'bl sym.imp.__aeabi_idiv'), (9131272, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9131380, 'blx r4'), (9131444, 'blx r2'), (9131600, 'blx r7'), (9131624, 'bl sym.imp.memset'), (9131676, 'blx lr'), (9131776, 'bl sym.imp.objc_enumerationMutation'), (9131884, 'blx ip'), (9131916, 'blx r3'), (9132056, 'blx r6'), (9132112, 'blx r3'), (9132148, 'blx ip'), (9132236, 'blx lr'), (9132268, 'blx r3'), (9132396, 'blx r6'), (9132452, 'blx r3'), (9132488, 'blx ip'), (9132564, 'bl loc.imp.objc_msgSend'), (9132596, 'bl loc.imp.objc_msgSend'), (9132632, 'bl loc.imp.objc_msgSend'), (9132672, 'blx r3'), (9132752, 'blx lr'), (9132780, 'blx r3'), (9132896, 'blx lr'), (9132928, 'blx r3'), (9133052, 'blx r5'), (9133108, 'blx r3'), (9133144, 'blx ip'), (9133212, 'bl loc.imp.objc_msgSend'), (9133248, 'bl loc.imp.objc_msgSend'), (9133288, 'blx r3'), (9133396, 'blx ip'), (9133484, 'blx r2')],
        branches=[(9131396, 'beq', 9133432), (9131452, 'bls', 9133428), (9131688, 'beq', 9133420), (9131768, 'beq', 9131780), (9131928, 'beq', 9132680), (9131944, 'bne', 9132152), (9132284, 'bne', 9132492), (9132676, 'b', 9133296), (9132800, 'beq', 9133292), (9132948, 'bne', 9133148), (9133292, 'b', 9133296), (9133296, 'b', 9133300), (9133324, 'blo', 9131732), (9133416, 'bne', 9131732), (9133420, 'b', 9133424), (9133424, 'b', 9133428), (9133428, 'b', 9133444), (9133440, 'b', 9133516), (9133492, 'bne', 9133508), (9133504, 'b', 9133516)],
    ),
    dict(
        name='dw_addwire',
        method='DynamicWorld -[addWireAtPos:ofType:saveDict:placedByClient:]',
        types='v28@0:4{?=ii}8i16@20@24',
        start=9353664,
        end=9353828,
        disasm='disasm_dynamicworld_addwireatpos.txt',
        base_add=9353756,
        base_literal=9353824,
        boundary='consecutive IMPs: [wireAtPos:] follows at 0x008eba64',
        selectors={9353820: (15216920, 'addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:')},
        imports={},
        ivars={},
        classes={},
        instructions=[(9353664, 'push {r4, r5, fp, lr}'), (9353788, 'mov r1, 0x26'), (9353808, 'bl loc.imp.objc_msgSend'), (9353816, 'pop {r4, r5, fp, pc}')],
        semantics=('Thin forwarder: [self addStandardObjectAtPos:pos objectType:0x26 itemType:type saveDict:saveDict placedByClient:placedByClient] - the constant 0x26 is the wire dynamic-object type tag staged on the outgoing stack frame (mov r1, 0x26; str r1, [r5]); position struct {x,y} and remaining args re-staged at [sp,4..0xc].'),
        calls=[(9353808, 'bl loc.imp.objc_msgSend')],
        branches=[],
    ),
    dict(
        name='dw_wireatpos',
        method='DynamicWorld -[wireAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9353828,
        end=9353940,
        disasm='disasm_dynamicworld_wireatpos.txt',
        base_add=9353888,
        base_literal=9353936,
        boundary='consecutive IMPs: [removeWireAtPos:] follows at 0x008ebad4',
        selectors={9353932: (15216868, 'objectOfType:atPos:')},
        imports={},
        ivars={},
        classes={},
        instructions=[(9353828, 'push {fp, lr}'), (9353920, 'bl loc.imp.objc_msgSend'), (9353928, 'pop {fp, pc}')],
        semantics=('Thin forward read: [self objectOfType:0x26 atPos:pos] - wire tag 0x26 again; returns the wire dynamic object at that position (nil if none).'),
        calls=[(9353920, 'bl loc.imp.objc_msgSend')],
        branches=[],
    ),
    dict(
        name='dw_removewire',
        method='DynamicWorld -[removeWireAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9353940,
        end=9354120,
        disasm='disasm_dynamicworld_removewireatpos.txt',
        base_add=9353956,
        base_literal=9354116,
        boundary='consecutive IMPs: next method at 0x008ebb88',
        selectors={9354104: (15216884, 'removeStandardObject:'), 9354108: (15216732, 'wireAtPos:')},
        imports={9354100: (17151904, 'objc_msgSend')},
        ivars={},
        classes={},
        instructions=[(9353940, 'push {r4, sl, fp, lr}'), (9354044, 'bl loc.imp.objc_msgSend'), (9354084, 'blx r3'), (9354096, 'pop {r4, sl, fp, pc}')],
        semantics=('Removal pair: wire = [self wireAtPos:pos]; when non-nil -> [self removeStandardObject:wire] (objc_msgSend trampoline blx); 0x26 wire tag reused through wireAtPos:.'),
        calls=[(9354044, 'bl loc.imp.objc_msgSend'), (9354084, 'blx r3')],
        branches=[],
    ),
    dict(
        name='wpc_init',
        method='WirePathCreator -[initWithWorld:]',
        types='@12@0:4@8',
        start=14360208,
        end=14360452,
        disasm='disasm_wirepathcreator_init.txt',
        base_add=14360224,
        base_literal=14360448,
        boundary='consecutive IMPs: [dealloc] follows at 0x00db1f84',
        selectors={14360432: (15240972, 'init')},
        imports={14360428: (17151900, 'objc_msgSendSuper2')},
        ivars={14360440: (17169112, 'OBJC_IVAR_$_WirePathCreator.derivedTilePropertiesArray', 20), 14360444: (17169116, 'OBJC_IVAR_$_WirePathCreator.world', 4)},
        classes={14360436: (15253324, 'OBJC_CLASS_$_WirePathCreator')},
        instructions=[(14360208, 'push {r4, r5, fp, lr}'), (14360296, 'blx lr'), (14360340, 'movw r0, 0x1800'), (14360424, 'pop {r4, r5, fp, pc}')],
        semantics=('objc_msgSendSuper2(super, init) -> nil guard; self.world@4 = world (arg); self.derivedTilePropertiesArray@20 = __wrap_malloc(0x1800) = 6144 bytes = 512 x 12-byte property slots (matches the 0x1ff=511 full check in tileDerivedPropertiesAtWorldIndex:); return self.'),
        calls=[(14360296, 'blx lr'), (14360376, 'bl sym.imp.__wrap_malloc')],
        branches=[(14360324, 'bne', 14360340), (14360336, 'b', 14360416)],
    ),
    dict(
        name='wpc_dealloc',
        method='WirePathCreator -[dealloc]',
        types='v8@0:4',
        start=14360452,
        end=14360756,
        disasm='disasm_wirepathcreator_dealloc.txt',
        base_add=14360468,
        base_literal=14360752,
        boundary='consecutive IMPs: next method at 0x00db20b4',
        selectors={14360724: (15240980, 'dealloc'), 14360736: (15240976, 'release')},
        imports={14360720: (17151900, 'objc_msgSendSuper2'), 14360732: (17151904, 'objc_msgSend')},
        ivars={14360740: (17169120, 'OBJC_IVAR_$_WirePathCreator.closedList', 12), 14360744: (17169124, 'OBJC_IVAR_$_WirePathCreator.openList', 8), 14360748: (17169112, 'OBJC_IVAR_$_WirePathCreator.derivedTilePropertiesArray', 20)},
        classes={14360728: (15253324, 'OBJC_CLASS_$_WirePathCreator')},
        instructions=[(14360452, 'push {r4, r5, r6, r7, fp, lr}'), (14360508, 'bl sym.imp.__wrap_free'), (14360632, 'blx lr'), (14360716, 'pop {r4, r5, r6, r7, fp, pc}')],
        semantics=('Teardown: __wrap_free(derivedTilePropertiesArray@20); release(openList@8); release(closedList@12); objc_msgSendSuper2(dealloc). derivedTileIndices@28 map is empty at dealloc time (find engine clears it on entry).'),
        calls=[(14360508, 'bl sym.imp.__wrap_free'), (14360632, 'blx lr'), (14360668, 'blx r3'), (14360708, 'blx r2')],
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
        'batch': 'electricity net-sync pair + wire forwarding + WirePathCreator lifecycle (World sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient: / electricityPathDataRecieved:fromClient: / DynamicWorld initialDynamicObjectsNetDataForMacroTileIndex:wireForClient: / addWireAtPos:ofType:saveDict:placedByClient: / wireAtPos: / removeWireAtPos: / WirePathCreator initWithWorld: + dealloc)',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'power_sync.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale power_sync.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
