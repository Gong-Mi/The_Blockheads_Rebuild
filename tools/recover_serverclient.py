#!/usr/bin/env python3
"""Hash-gated recovery of the ServerClient (E150).

ServerClient lands: the batch sweeps serverclient surface:
42 bodies, 4913 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/SERVERCLIENT.md for the prose and boundaries.
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
    'bl 0xd0ada4': 0x00d0ada4,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl method.std::__1::__tree_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int______std::__1::__map_value_compare_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___true___std::__1::allocator_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.__tree_std::__1::__map_value_compare_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___true__const_': 0x00d0d0c4,
    'bl method.std::__1::__tree_std::__1::pair_unsigned_int__unsigned_char___std::__1::__map_value_compare_unsigned_int__unsigned_char__std::__1::less_unsigned_int___true___std::__1::allocator_std::__1::pair_unsigned_int__unsigned_char_____.___tree__': 0x00d0d1a4,
    'bl method.std::__1::__tree_std::__1::pair_unsigned_int__unsigned_char___std::__1::__map_value_compare_unsigned_int__unsigned_char__std::__1::less_unsigned_int___true___std::__1::allocator_std::__1::pair_unsigned_int__unsigned_char_____.__tree_std::__1::__map_value_compare_unsigned_int__unsigned_char__std::__1::less_unsigned_int___true__const_': 0x00d0bcd0,
    'bl method.std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__tree_std::__1::less_unsigned_int__const_': 0x00d0cfe4,
    'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________._map__': 0x00d0837c,
    'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.at_unsigned_int_const_': 0x008ba928,
    'bl method.std::__1::map_unsigned_int__unsigned_char__std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__unsigned_char_____._map__': 0x00d0bc34,
    'bl method.std::__1::map_unsigned_int__unsigned_char__std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__unsigned_char_____.operator___unsigned_int_': 0x00d08514,
    'bl method.std::__1::pair_std::__1::__tree_iterator_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int______std::__1::__tree_node_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int______void___int___bool__std::__1::__tree_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int______std::__1::__map_value_compare_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___true___std::__1::allocator_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________::__insert_unique_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1.allocator_unsigned_int_______std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____': 0x00d0c520,
    'bl method.std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___._set__': 0x00d0834c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap__ZdlPv': 0x001c3d88,
    'bl sym.imp.__wrap__Znwm': 0x001c3da0,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
}

SPECS = [
    dict(
        name='svc_00',
        method='ServerClient -[.cxx_construct]',
        types='@8@0:4',
        start=13679716,
        end=13679824,
        disasm='disasm_worldtileloader_svc_00.txt',
        base_add=13679732,
        base_literal=13679820,
        boundary='ARM.exidx end 0x00d0bcd0 (listing bound); next ObjC IMP 0x00d0d604 CherryTree -[objectType]',
        selectors={},
        imports={},
        ivars={
                 0xd0bcc8: (17168124, 'OBJC_IVAR_$_ServerClient.requestedBlockRequestTypes', 16),
        },
        classes={},
        instructions=[(13679716, 'push {fp, lr}'), (13679820, 'eorseq r3, r5, r8, ror lr')],
        calls=[(13679792, 'bl method.std::__1::__tree_std::__1::pair_unsigned_int__unsigned_char___std::__1::__map_value_compare_unsigned_int__unsigned_char__std::__1::less_unsigned_int___true___std::__1::allocator_std::__1::pair_unsigned_int__unsigned_char_____.__tree_std::__1::__map_value_compare_unsigned_int__unsigned_char__std::__1::less_unsigned_int___true__const_')],
        branches=[],
        semantics=('[ServerClient -[.cxx_construct]] (imp 0x00d0bc64, 27w): -[.cxx_construct] (0xd0bc64, 27w): default-constructs the single C++ ivar requestedBlockRequestTypes@16 (std::map<unsigned int, unsigned char>) via the local std::__1::__tree ctor bl 0xd0bcd0; every ObjC ivar is left to allocation-time zeroing (root class, no super)..\n'),
    ),
    dict(
        name='svc_01',
        method='ServerClient -[.cxx_destruct]',
        types='v8@0:4',
        start=13679596,
        end=13679716,
        disasm='disasm_worldtileloader_svc_01.txt',
        base_add=13679612,
        base_literal=13679664,
        boundary='ARM.exidx end 0x00d0bcd0; body trimmed at the next IMP 0x00d0bc64 ServerClient -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0xd0bc2c: (17168124, 'OBJC_IVAR_$_ServerClient.requestedBlockRequestTypes', 16),
        },
        classes={},
        instructions=[(13679596, 'push {fp, lr}'), (13679712, 'pop {fp, pc}')],
        calls=[(13679644, 'bl method.std::__1::map_unsigned_int__unsigned_char__std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__unsigned_char_____._map__'), (13679692, 'bl method.std::__1::__tree_std::__1::pair_unsigned_int__unsigned_char___std::__1::__map_value_compare_unsigned_int__unsigned_char__std::__1::less_unsigned_int___true___std::__1::allocator_std::__1::pair_unsigned_int__unsigned_char_____.___tree__')],
        branches=[],
        semantics=('[ServerClient -[.cxx_destruct]] (imp 0x00d0bbec, 30w): -[.cxx_destruct] (0xd0bbec, 30w): destroys requestedBlockRequestTypes@16 via bl 0xd0bc34 = std::map<unsigned int,unsigned char>::~map() (out-of-batch local helper; its 0xd0bc34..0xd0bc60 rows sit inside this trimmed listing). ObjC releases live in dealloc, not here..\n'),
    ),
    dict(
        name='svc_02',
        method='ServerClient -[addCreationDataUpdateObjectDataToSend:ofType:]',
        types='v16@0:4@8C12',
        start=13668600,
        end=13668860,
        disasm='disasm_worldtileloader_svc_02.txt',
        base_add=13668616,
        base_literal=13668856,
        boundary='ARM.exidx end 0x00d091fc (listing bound); next ObjC IMP 0x00d091fc ServerClient -[addUpdateObjectDataToSend:ofType:reliable:]',
        selectors={
                 0xd091e4: (15238160, 'addObject:'),
                 0xd091e8: (15238080, 'objectForKey:'),
                 0xd091ec: (15238096, 'numberWithInt:'),
        },
        imports={
                 0xd091e0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd091f4: (17168064, 'OBJC_IVAR_$_ServerClient.creationDataUpdateArraysToSend', 44),
        },
        classes={
                 0xd091f0: (15251140, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(13668600, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13668856, 'eorseq r6, r5, r4, ror 19')],
        calls=[(13668756, 'blx lr'), (13668788, 'blx r3'), (13668820, 'blx r3')],
        branches=[],
        semantics=('[ServerClient -[addCreationDataUpdateObjectDataToSend:ofType:]] (imp 0x00d090f8, 65w): -[addCreationDataUpdateObjectDataToSend:ofType:] (0xd090f8, 65w): [[self->creationDataUpdateArraysToSend@44 objectForKey:[NSNumber numberWithInt:ofType]] addObject:objectData]; the per-type array is expected to pre-exist (no create-if-missing in this path)..\n'),
    ),
    dict(
        name='svc_03',
        method='ServerClient -[addCreationObjectDataToSend:ofType:objectID:]',
        types='v24@0:4@8C12Q16',
        start=13667468,
        end=13668600,
        disasm='disasm_worldtileloader_svc_03.txt',
        base_add=13667484,
        base_literal=13668596,
        boundary='ARM.exidx end 0x00d090f8 (listing bound); next ObjC IMP 0x00d090f8 ServerClient -[addCreationDataUpdateObjectDataToSend:ofType:]',
        selectors={
                 0xd090bc: (15238164, 'count'),
                 0xd090c0: (15238080, 'objectForKey:'),
                 0xd090c4: (15238096, 'numberWithInt:'),
                 0xd090d0: (15238160, 'addObject:'),
                 0xd090d8: (15238172, 'countByEnumeratingWithState:objects:count:'),
                 0xd090dc: (15238168, 'indexSet'),
                 0xd090e4: (15238176, 'getBytes:length:'),
                 0xd090ec: (15238148, 'addIndex:'),
                 0xd090f0: (15238180, 'removeObjectsAtIndexes:'),
        },
        imports={
                 0xd090b8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd090cc: (17168056, 'OBJC_IVAR_$_ServerClient.removalArraysToSend', 52),
                 0xd090d4: (17168072, 'OBJC_IVAR_$_ServerClient.creationArraysToSend', 36),
        },
        classes={
                 0xd090c8: (15251140, 'OBJC_CLASS_$_NSNumber'),
                 0xd090e0: (15251128, 'OBJC_CLASS_$_NSMutableIndexSet'),
        },
        instructions=[(13667468, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13668596, 'eorseq r6, r5, r0, asr lr')],
        calls=[(13667716, 'blx r3'), (13667748, 'blx r3'), (13667780, 'blx r3'), (13667836, 'blx r3'), (13667868, 'blx r3'), (13667892, 'blx r2'), (13668016, 'blx r2'), (13668052, 'bl sym.imp.memset'), (13668100, 'blx lr'), (13668200, 'bl sym.imp.objc_enumerationMutation'), (13668244, 'bl loc.imp.objc_msgSend'), (13668336, 'blx r3'), (13668448, 'blx ip'), (13668524, 'blx r3')],
        branches=[(13667900, 'bls', 13668528), (13668112, 'beq', 13668472), (13668192, 'beq', 13668204), (13668280, 'bne', 13668340), (13668284, 'b', 13668288), (13668376, 'blo', 13668156), (13668468, 'bne', 13668156), (13668472, 'b', 13668476)],
        semantics=('[ServerClient -[addCreationObjectDataToSend:ofType:objectID:]] (imp 0x00d08c8c, 283w): -[addCreationObjectDataToSend:ofType:objectID:] (0xd08c8c, 283w): (1) [[creationArraysToSend@36 objectForKey:NSNumber(ofType)] addObject:objectData]; (2) fetch removalArraysToSend@52[NSNumber(ofType)]; (3) if [count]>0: fast-enumerate it ([elem getBytes:buf length:8]) and [removeObjectsAtIndexes:is] every entry whose first 8 bytes == the 64-bit objectID. i.e. a queued creation cancels queued removals of the same object (64-bit ID compare halves: fp-0x38 low / fp-0x34 high)..\n'),
    ),
    dict(
        name='svc_04',
        method='ServerClient -[addFillRequest:]',
        types='v12@0:4I8',
        start=13676304,
        end=13676496,
        disasm='disasm_worldtileloader_svc_04.txt',
        base_add=13676320,
        base_literal=13676492,
        boundary='ARM.exidx end 0x00d0afd0 (listing bound); next ObjC IMP 0x00d0afd0 ServerClient -[getAndRemoveAllRecieptDataForMacroPos:world:]',
        selectors={
                 0xd0afbc: (15238160, 'addObject:'),
                 0xd0afc0: (15238208, 'numberWithUnsignedInt:'),
        },
        imports={
                 0xd0afb8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd0afc8: (17168120, 'OBJC_IVAR_$_ServerClient.fillIndices', 68),
        },
        classes={
                 0xd0afc4: (15251140, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(13676304, 'push {r4, r5, r6, r7, fp, lr}'), (13676492, 'eorseq r4, r5, ip, asr 23')],
        calls=[(13676428, 'blx ip'), (13676460, 'blx r3')],
        branches=[],
        semantics=('[ServerClient -[addFillRequest:]] (imp 0x00d0af10, 48w): -[addFillRequest:] (0xd0af10, 48w): [fillIndices@68 addObject:[NSNumber numberWithUnsignedInt:blockIndex]] -- records an outstanding fill receipt; drained by getAndRemoveAllRecieptDataForMacroPos:world:..\n'),
    ),
    dict(
        name='svc_05',
        method='ServerClient -[addRemovalObjectDataToSend:ofType:objectID:]',
        types='v24@0:4@8C12Q16',
        start=13669348,
        end=13672128,
        disasm='disasm_worldtileloader_svc_05.txt',
        base_add=13669364,
        base_literal=13672124,
        boundary='ARM.exidx end 0x00d09ec0 (listing bound); next ObjC IMP 0x00d09ec0 ServerClient -[sendAllObjectData]',
        selectors={
                 0xd09e74: (15238164, 'count'),
                 0xd09e78: (15238080, 'objectForKey:'),
                 0xd09e7c: (15238096, 'numberWithInt:'),
                 0xd09e88: (15238160, 'addObject:'),
                 0xd09e90: (15238172, 'countByEnumeratingWithState:objects:count:'),
                 0xd09e94: (15238168, 'indexSet'),
                 0xd09e9c: (15238176, 'getBytes:length:'),
                 0xd09ea4: (15238148, 'addIndex:'),
                 0xd09ea8: (15238180, 'removeObjectsAtIndexes:'),
        },
        imports={
                 0xd09e70: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd09e84: (17168072, 'OBJC_IVAR_$_ServerClient.creationArraysToSend', 36),
                 0xd09e8c: (17168056, 'OBJC_IVAR_$_ServerClient.removalArraysToSend', 52),
                 0xd09eac: (17168068, 'OBJC_IVAR_$_ServerClient.updateArraysToSend', 40),
                 0xd09eb4: (17168064, 'OBJC_IVAR_$_ServerClient.creationDataUpdateArraysToSend', 44),
        },
        classes={
                 0xd09e80: (15251140, 'OBJC_CLASS_$_NSNumber'),
                 0xd09e98: (15251128, 'OBJC_CLASS_$_NSMutableIndexSet'),
        },
        instructions=[(13669348, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13672124, 'ldrshteq r6, [r5], -r8')],
        calls=[(13669596, 'blx r3'), (13669628, 'blx r3'), (13669660, 'blx r3'), (13669716, 'blx r3'), (13669748, 'blx r3'), (13669772, 'blx r2'), (13669896, 'blx r2'), (13669932, 'bl sym.imp.memset'), (13669980, 'blx lr'), (13670080, 'bl sym.imp.objc_enumerationMutation'), (13670124, 'bl loc.imp.objc_msgSend'), (13670216, 'blx r3'), (13670328, 'blx ip'), (13670404, 'blx r3'), (13670532, 'blx r4'), (13670564, 'blx r3'), (13670588, 'blx r2'), (13670712, 'blx r2'), (13670748, 'bl sym.imp.memset'), (13670796, 'blx lr'), (13670896, 'bl sym.imp.objc_enumerationMutation'), (13670940, 'bl loc.imp.objc_msgSend'), (13671032, 'blx r3'), (13671144, 'blx ip'), (13671220, 'blx r3'), (13671348, 'blx r4'), (13671380, 'blx r3'), (13671404, 'blx r2'), (13671528, 'blx r2'), (13671564, 'bl sym.imp.memset'), (13671612, 'blx lr'), (13671712, 'bl sym.imp.objc_enumerationMutation'), (13671756, 'bl loc.imp.objc_msgSend'), (13671848, 'blx r3'), (13671960, 'blx ip'), (13672036, 'blx r3')],
        branches=[(13669780, 'bls', 13670408), (13669992, 'beq', 13670352), (13670072, 'beq', 13670084), (13670160, 'bne', 13670220), (13670164, 'b', 13670168), (13670256, 'blo', 13670036), (13670348, 'bne', 13670036), (13670352, 'b', 13670356), (13670596, 'bls', 13671224), (13670808, 'beq', 13671168), (13670888, 'beq', 13670900), (13670976, 'bne', 13671036), (13670980, 'b', 13670984), (13671072, 'blo', 13670852), (13671164, 'bne', 13670852), (13671168, 'b', 13671172), (13671412, 'bls', 13672040), (13671624, 'beq', 13671984), (13671704, 'beq', 13671716), (13671792, 'bne', 13671852), (13671796, 'b', 13671800), (13671888, 'blo', 13671668), (13671980, 'bne', 13671668), (13671984, 'b', 13671988)],
        semantics=('[ServerClient -[addRemovalObjectDataToSend:ofType:objectID:]] (imp 0x00d093e4, 695w): -[addRemovalObjectDataToSend:ofType:objectID:] (0xd093e4, 695w): (1) [[removalArraysToSend@52 objectForKey:NSNumber(ofType)] addObject:objectData]; (2) then, for each of creationArraysToSend@36, updateArraysToSend@40, creationDataUpdateArraysToSend@44: fetch [Q objectForKey:NSNumber(ofType)] and if [count]>0 fast-enumerate, getBytes:length:8 per element, removeObjectsAtIndexes: those whose first 8 bytes == objectID. updateUnreliableArraysToSend@48 is NOT scanned (as compiled)..\n'),
    ),
    dict(
        name='svc_06',
        method='ServerClient -[addUpdateObjectDataToSend:ofType:reliable:]',
        types='v20@0:4@8C12c16',
        start=13668860,
        end=13669348,
        disasm='disasm_worldtileloader_svc_06.txt',
        base_add=13668876,
        base_literal=13669344,
        boundary='ARM.exidx end 0x00d093e4 (listing bound); next ObjC IMP 0x00d093e4 ServerClient -[addRemovalObjectDataToSend:ofType:objectID:]',
        selectors={
                 0xd093c8: (15238160, 'addObject:'),
                 0xd093cc: (15238080, 'objectForKey:'),
                 0xd093d0: (15238096, 'numberWithInt:'),
        },
        imports={
                 0xd093c4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd093d8: (17168060, 'OBJC_IVAR_$_ServerClient.updateUnreliableArraysToSend', 48),
                 0xd093dc: (17168068, 'OBJC_IVAR_$_ServerClient.updateArraysToSend', 40),
        },
        classes={
                 0xd093d4: (15251140, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(13668860, 'push {r4, r5, r6, r7, fp, lr}'), (13669344, 'eorseq r6, r5, r0, ror 17')],
        calls=[(13669044, 'blx r4'), (13669076, 'blx r3'), (13669108, 'blx r3'), (13669240, 'blx r4'), (13669272, 'blx r3'), (13669304, 'blx r3')],
        branches=[(13668916, 'beq', 13669116), (13669112, 'b', 13669308)],
        semantics=('[ServerClient -[addUpdateObjectDataToSend:ofType:reliable:]] (imp 0x00d091fc, 122w): -[addUpdateObjectDataToSend:ofType:reliable:] (0xd091fc, 122w): reliable (char, stack arg fp+8): if nonzero -> [[updateArraysToSend@40 objectForKey:NSNumber(ofType)] addObject:objectData]; else the same against updateUnreliableArraysToSend@48..\n'),
    ),
    dict(
        name='svc_07',
        method='ServerClient -[allLightBlockIndices]',
        types='@8@0:4',
        start=13679528,
        end=13679596,
        disasm='disasm_worldtileloader_svc_07.txt',
        base_add=13679552,
        base_literal=13679592,
        boundary='ARM.exidx end 0x00d0bbec (listing bound); next ObjC IMP 0x00d0bbec ServerClient -[.cxx_destruct]',
        selectors={},
        imports={},
        ivars={
                 0xd0bbe4: (17168112, 'OBJC_IVAR_$_ServerClient.allLightBlockIndices', 84),
        },
        classes={},
        instructions=[(13679528, 'sub sp, sp, 0xc'), (13679592, 'eorseq r3, r5, ip, lsr 30')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[allLightBlockIndices]] (imp 0x00d0bba8, 17w): -[allLightBlockIndices] (0xd0bba8, 17w): plain getter for allLightBlockIndices@84 (Apportable offset-cell read behind dmb ish)..\n'),
    ),
    dict(
        name='svc_08',
        method='ServerClient -[blockIsRequested:]',
        types='c12@0:4i8',
        start=13666628,
        end=13666740,
        disasm='disasm_worldtileloader_svc_08.txt',
        base_add=13666644,
        base_literal=13666736,
        boundary='ARM.exidx end 0x00d08ad8; body trimmed at the next IMP 0x00d089b4 ServerClient -[removeBlockRequest:]',
        selectors={},
        imports={},
        ivars={
                 0xd089ac: (17168124, 'OBJC_IVAR_$_ServerClient.requestedBlockRequestTypes', 16),
        },
        classes={},
        instructions=[(13666628, 'push {fp, lr}'), (13666736, 'mlaseq r5, r8, r1, r7')],
        calls=[(13666696, 'bl method.std::__1::map_unsigned_int__unsigned_char__std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__unsigned_char_____.operator___unsigned_int_')],
        branches=[],
        semantics=('[ServerClient -[blockIsRequested:]] (imp 0x00d08944, 28w): -[blockIsRequested:] (0xd08944, 28w): return (signed char)(self->requestedBlockRequestTypes@16[i] != 0); the std::map operator[](unsigned int) call is the compiled read form (it also inserts a 0 entry for a missing key -- side effect transcribed as compiled)..\n'),
    ),
    dict(
        name='svc_09',
        method='ServerClient -[blockIsWired:]',
        types='c12@0:4i8',
        start=13666516,
        end=13666628,
        disasm='disasm_worldtileloader_svc_09.txt',
        base_add=13666532,
        base_literal=13666624,
        boundary='ARM.exidx end 0x00d08944 (listing bound); next ObjC IMP 0x00d08944 ServerClient -[blockIsRequested:]',
        selectors={
                 0xd08938: (15238152, 'containsIndex:'),
        },
        imports={
                 0xd08934: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd0893c: (17168088, 'OBJC_IVAR_$_ServerClient.wiredBlocks', 28),
        },
        classes={},
        instructions=[(13666516, 'push {r4, sl, fp, lr}'), (13666624, 'eorseq r7, r5, r8, lsl 4')],
        calls=[(13666596, 'blx ip')],
        branches=[],
        semantics=('[ServerClient -[blockIsWired:]] (imp 0x00d088d4, 28w): -[blockIsWired:] (0xd088d4, 28w): return (signed char)[self->wiredBlocks@28 containsIndex:i]..\n'),
    ),
    dict(
        name='svc_10',
        method='ServerClient -[blockRemoved:]',
        types='v12@0:4i8',
        start=13667032,
        end=13667140,
        disasm='disasm_worldtileloader_svc_10.txt',
        base_add=13667048,
        base_literal=13667136,
        boundary='ARM.exidx end 0x00d08b44 (listing bound); next ObjC IMP 0x00d08b44 ServerClient -[dynamicObjectIsWired:]',
        selectors={
                 0xd08b38: (15238156, 'removeIndex:'),
        },
        imports={
                 0xd08b34: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd08b3c: (17168088, 'OBJC_IVAR_$_ServerClient.wiredBlocks', 28),
        },
        classes={},
        instructions=[(13667032, 'push {r4, sl, fp, lr}'), (13667136, 'eorseq r7, r5, r4')],
        calls=[(13667112, 'blx ip')],
        branches=[],
        semantics=('[ServerClient -[blockRemoved:]] (imp 0x00d08ad8, 27w): -[blockRemoved:] (0xd08ad8, 27w): [self->wiredBlocks@28 removeIndex:i]; void (marks the block as no longer wired/held by this client)..\n'),
    ),
    dict(
        name='svc_11',
        method='ServerClient -[clientID]',
        types='@8@0:4',
        start=13678596,
        end=13678664,
        disasm='disasm_worldtileloader_svc_11.txt',
        base_add=13678620,
        base_literal=13678660,
        boundary='ARM.exidx end 0x00d0b848 (listing bound); next ObjC IMP 0x00d0b848 ServerClient -[isAdmin]',
        selectors={},
        imports={},
        ivars={
                 0xd0b840: (17168108, 'OBJC_IVAR_$_ServerClient.clientID', 4),
        },
        classes={},
        instructions=[(13678596, 'sub sp, sp, 0xc'), (13678660, 'ldrsbteq r4, [r5], -r0')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[clientID]] (imp 0x00d0b804, 17w): -[clientID] (0xd0b804, 17w): getter for clientID@4 (NSString, the peer/player ID used as GKMatch send target and admin lookup key)..\n'),
    ),
    dict(
        name='svc_12',
        method='ServerClient -[clientReconnected]',
        types='v8@0:4',
        start=13662320,
        end=13664092,
        disasm='disasm_worldtileloader_svc_12.txt',
        base_add=13662336,
        base_literal=13664088,
        boundary='ARM.exidx end 0x00d07f5c (listing bound); next ObjC IMP 0x00d07f5c ServerClient -[dealloc]',
        selectors={
                 0xd07ef8: (15238140, 'removeAllObjects'),
                 0xd07f14: (15238136, 'removeAllIndexes'),
                 0xd07f28: (15238084, 'playerIsAdminWithAlias:'),
                 0xd07f30: (15238080, 'objectForKey:'),
                 0xd07f34: (15238076, 'playerInfoForPeerID:'),
                 0xd07f44: (15238100, 'setObject:forKey:'),
                 0xd07f48: (15238096, 'numberWithInt:'),
                 0xd07f50: (15238092, 'array'),
        },
        imports={
                 0xd07ef4: (17151904, 'objc_msgSend'),
                 0xd07f2c: (16440888, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd07efc: (17168056, 'OBJC_IVAR_$_ServerClient.removalArraysToSend', 52),
                 0xd07f00: (17168060, 'OBJC_IVAR_$_ServerClient.updateUnreliableArraysToSend', 48),
                 0xd07f04: (17168064, 'OBJC_IVAR_$_ServerClient.creationDataUpdateArraysToSend', 44),
                 0xd07f08: (17168068, 'OBJC_IVAR_$_ServerClient.updateArraysToSend', 40),
                 0xd07f0c: (17168072, 'OBJC_IVAR_$_ServerClient.creationArraysToSend', 36),
                 0xd07f10: (17168120, 'OBJC_IVAR_$_ServerClient.fillIndices', 68),
                 0xd07f18: (17168080, 'OBJC_IVAR_$_ServerClient.requestedBlockIndices', 12),
                 0xd07f1c: (17168084, 'OBJC_IVAR_$_ServerClient.wiredDynamicObjects', 32),
                 0xd07f20: (17168088, 'OBJC_IVAR_$_ServerClient.wiredBlocks', 28),
                 0xd07f24: (17168096, 'OBJC_IVAR_$_ServerClient.isAdmin', 78),
                 0xd07f38: (17168108, 'OBJC_IVAR_$_ServerClient.clientID', 4),
                 0xd07f3c: (17168100, 'OBJC_IVAR_$_ServerClient.server', 8),
                 0xd07f40: (17168116, 'OBJC_IVAR_$_ServerClient.connected', 77),
        },
        classes={
                 0xd07f4c: (15251140, 'OBJC_CLASS_$_NSNumber'),
                 0xd07f54: (15251136, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(13662320, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13664088, 'eorseq r8, r5, ip, ror 4')],
        calls=[(13662748, 'blx ip'), (13662768, 'blx r3'), (13662800, 'blx r3'), (13662856, 'blx ip'), (13662892, 'blx r3'), (13662928, 'blx r3'), (13662964, 'blx r3'), (13663000, 'blx r3'), (13663036, 'blx r3'), (13663072, 'blx r3'), (13663108, 'blx r3'), (13663144, 'blx r3'), (13663372, 'blx r2'), (13663412, 'blx r3'), (13663448, 'blx ip'), (13663500, 'blx r3'), (13663540, 'blx r3'), (13663576, 'blx ip'), (13663628, 'blx r3'), (13663668, 'blx r3'), (13663704, 'blx ip'), (13663756, 'blx r3'), (13663796, 'blx r3'), (13663832, 'blx ip'), (13663884, 'blx r3'), (13663924, 'blx r3'), (13663960, 'blx ip')],
        branches=[(13663168, 'bge', 13663980), (13663976, 'b', 13663160)],
        semantics=('[ServerClient -[clientReconnected]] (imp 0x00d07870, 443w): -[clientReconnected] (0xd07870, 443w): full reconnect refresh: connected@77=1; isAdmin@78 = (s8)[server@8 playerIsAdminWithAlias:[[server playerInfoForPeerID:clientID@4] objectForKey:<CFString "alias">]]; removeAllIndexes on wiredBlocks@28, wiredDynamicObjects@32, requestedBlockIndices@12; removeAllObjects on fillIndices@68 + creation@36/update@40/creationDataUpdate@44/updateUnreliable@48/removal@52 dicts; then for i in 0..0x40: [D setObject:[NSMutableArray array] forKey:[NSNumber numberWithInt:i]] for each of the 5 dicts. paused@76 untouched..\n'),
    ),
    dict(
        name='svc_13',
        method='ServerClient -[connected]',
        types='c8@0:4',
        start=13678340,
        end=13678400,
        disasm='disasm_worldtileloader_svc_13.txt',
        base_add=13678348,
        base_literal=13678396,
        boundary='ARM.exidx end 0x00d0b740 (listing bound); next ObjC IMP 0x00d0b740 ServerClient -[requestedBlockIndices]',
        selectors={},
        imports={},
        ivars={
                 0xd0b738: (17168116, 'OBJC_IVAR_$_ServerClient.connected', 77),
        },
        classes={},
        instructions=[(13678340, 'sub sp, sp, 8'), (13678396, 'eorseq r4, r5, r0, ror 7')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[connected]] (imp 0x00d0b704, 15w): -[connected] (0xd0b704, 15w): getter for connected@77 (char)..\n'),
    ),
    dict(
        name='svc_14',
        method='ServerClient -[createIfNotCreatedForBlockRequest:]',
        types='c12@0:4i8',
        start=13666920,
        end=13667032,
        disasm='disasm_worldtileloader_svc_14.txt',
        base_add=13666936,
        base_literal=13667028,
        boundary='ARM.exidx end 0x00d08ad8 (listing bound); next ObjC IMP 0x00d08ad8 ServerClient -[blockRemoved:]',
        selectors={},
        imports={},
        ivars={
                 0xd08ad0: (17168124, 'OBJC_IVAR_$_ServerClient.requestedBlockRequestTypes', 16),
        },
        classes={},
        instructions=[(13666920, 'push {fp, lr}'), (13667028, 'eorseq r7, r5, r4, ror r0')],
        calls=[(13666988, 'bl method.std::__1::map_unsigned_int__unsigned_char__std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__unsigned_char_____.operator___unsigned_int_')],
        branches=[],
        semantics=('[ServerClient -[createIfNotCreatedForBlockRequest:]] (imp 0x00d08a68, 28w): -[createIfNotCreatedForBlockRequest:] (0xd08a68, 28w): return (signed char)(requestedBlockRequestTypes@16[i] == 1); the operator[] call both reads and inserts the 0 entry when the key is absent -- the \'create\' half of the name is just that map insert..\n'),
    ),
    dict(
        name='svc_15',
        method='ServerClient -[dealloc]',
        types='v8@0:4',
        start=13664092,
        end=13665100,
        disasm='disasm_worldtileloader_svc_15.txt',
        base_add=13664108,
        base_literal=13665096,
        boundary='ARM.exidx end 0x00d0834c (listing bound); next ObjC IMP 0x00d083ac ServerClient -[requestForBlock:]',
        selectors={
                 0xd0830c: (15238144, 'dealloc'),
                 0xd08318: (15238132, 'release'),
        },
        imports={
                 0xd08308: (17151900, 'objc_msgSendSuper2'),
                 0xd08314: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd08304: (17168052, 'OBJC_IVAR_$_ServerClient.worldIndicesContainingTamedAnimals', 72),
                 0xd0831c: (17168112, 'OBJC_IVAR_$_ServerClient.allLightBlockIndices', 84),
                 0xd08320: (17168120, 'OBJC_IVAR_$_ServerClient.fillIndices', 68),
                 0xd08324: (17168056, 'OBJC_IVAR_$_ServerClient.removalArraysToSend', 52),
                 0xd08328: (17168060, 'OBJC_IVAR_$_ServerClient.updateUnreliableArraysToSend', 48),
                 0xd0832c: (17168064, 'OBJC_IVAR_$_ServerClient.creationDataUpdateArraysToSend', 44),
                 0xd08330: (17168068, 'OBJC_IVAR_$_ServerClient.updateArraysToSend', 40),
                 0xd08334: (17168072, 'OBJC_IVAR_$_ServerClient.creationArraysToSend', 36),
                 0xd08338: (17168084, 'OBJC_IVAR_$_ServerClient.wiredDynamicObjects', 32),
                 0xd0833c: (17168080, 'OBJC_IVAR_$_ServerClient.requestedBlockIndices', 12),
                 0xd08340: (17168088, 'OBJC_IVAR_$_ServerClient.wiredBlocks', 28),
                 0xd08344: (17168108, 'OBJC_IVAR_$_ServerClient.clientID', 4),
        },
        classes={
                 0xd08310: (15253252, 'OBJC_CLASS_$_ServerClient'),
        },
        instructions=[(13664092, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13665096, 'eorseq r7, r5, r0, lsl 23')],
        calls=[(13664188, 'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.at_unsigned_int_const_'), (13664216, 'bl method.std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___._set__'), (13664232, 'bl sym.imp.__wrap__ZdlPv'), (13664304, 'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________._map__'), (13664320, 'bl sym.imp.__wrap__ZdlPv'), (13664616, 'blx lr'), (13664652, 'blx r3'), (13664688, 'blx r3'), (13664724, 'blx r3'), (13664760, 'blx r3'), (13664796, 'blx r3'), (13664832, 'blx r3'), (13664868, 'blx r3'), (13664904, 'blx r3'), (13664940, 'blx r3'), (13664976, 'blx r3'), (13665016, 'blx r2')],
        branches=[(13664144, 'bge', 13664256), (13664208, 'beq', 13664236), (13664236, 'b', 13664240), (13664252, 'b', 13664136), (13664296, 'beq', 13664324)],
        semantics=('[ServerClient -[dealloc]] (imp 0x00d07f5c, 252w): -[dealloc] (0xd07f5c, 252w): (P1) for i in 0..0x40: s = worldIndicesContainingTamedAnimals@72->at(i); if (s) { ~set(); operator delete(s); } (P2) if (map) { ~map(); operator delete(map); } then worldIndicesContainingTamedAnimals@72 = 0; (P3) releases exactly 11 ivars in order clientID@4, wiredBlocks@28, requestedBlockIndices@12, wiredDynamicObjects@32, creationArraysToSend@36, updateArraysToSend@40, creationDataUpdateArraysToSend@44, updateUnreliableArraysToSend@48, removalArraysToSend@52, fillIndices@68, allLightBlockIndices@84 (server@8, foundItemsList@80, lightBlockDatabase@88 are NOT released); (P4) super dealloc via objc_msgSendSuper2 with struct {self, ServerClient cls 0x00E919D0}..\n'),
    ),
    dict(
        name='svc_16',
        method='ServerClient -[dynamicObjectIsWired:]',
        types='c12@0:4I8',
        start=13667140,
        end=13667252,
        disasm='disasm_worldtileloader_svc_16.txt',
        base_add=13667156,
        base_literal=13667248,
        boundary='ARM.exidx end 0x00d08bb4 (listing bound); next ObjC IMP 0x00d08bb4 ServerClient -[wireDynamicObject:]',
        selectors={
                 0xd08ba8: (15238152, 'containsIndex:'),
        },
        imports={
                 0xd08ba4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd08bac: (17168084, 'OBJC_IVAR_$_ServerClient.wiredDynamicObjects', 32),
        },
        classes={},
        instructions=[(13667140, 'push {r4, sl, fp, lr}'), (13667248, 'mlaseq r5, r8, pc, r6')],
        calls=[(13667220, 'blx ip')],
        branches=[],
        semantics=('[ServerClient -[dynamicObjectIsWired:]] (imp 0x00d08b44, 28w): -[dynamicObjectIsWired:] (0xd08b44, 28w): return (signed char)[self->wiredDynamicObjects@32 containsIndex:objID (unsigned int)]..\n'),
    ),
    dict(
        name='svc_17',
        method='ServerClient -[foundItemsList]',
        types='@8@0:4',
        start=13679460,
        end=13679528,
        disasm='disasm_worldtileloader_svc_17.txt',
        base_add=13679484,
        base_literal=13679524,
        boundary='ARM.exidx end 0x00d0bbec; body trimmed at the next IMP 0x00d0bba8 ServerClient -[allLightBlockIndices]',
        selectors={},
        imports={},
        ivars={
                 0xd0bba0: (17168076, 'OBJC_IVAR_$_ServerClient.foundItemsList', 80),
        },
        classes={},
        instructions=[(13679460, 'sub sp, sp, 0xc'), (13679524, 'eorseq r3, r5, r0, ror pc')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[foundItemsList]] (imp 0x00d0bb64, 17w): -[foundItemsList] (0xd0bb64, 17w): getter for foundItemsList@80 (NSMutableIndexSet; the mining \'found item\' bookkeeping captured because the client is offline)..\n'),
    ),
    dict(
        name='svc_18',
        method='ServerClient -[getAndRemoveAllRecieptDataForMacroPos:world:]',
        types='@20@0:4{?=ii}8@16',
        start=13676496,
        end=13677500,
        disasm='disasm_worldtileloader_svc_18.txt',
        base_add=13676512,
        base_literal=13677496,
        boundary='ARM.exidx end 0x00d0b3bc (listing bound); next ObjC IMP 0x00d0b3bc ServerClient -[saveLightBlockIndices]',
        selectors={
                 0xd0b390: (15238172, 'countByEnumeratingWithState:objects:count:'),
                 0xd0b398: (15238092, 'array'),
                 0xd0b3a0: (15238212, 'unsignedIntValue'),
                 0xd0b3a8: (15238216, 'worldWidthMacro'),
                 0xd0b3ac: (15238160, 'addObject:'),
                 0xd0b3b0: (15238164, 'count'),
                 0xd0b3b4: (15238220, 'removeObjectsInArray:'),
        },
        imports={
                 0xd0b38c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd0b394: (17168120, 'OBJC_IVAR_$_ServerClient.fillIndices', 68),
        },
        classes={
                 0xd0b39c: (15251136, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(13676496, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13677496, 'eorseq r4, r5, ip, lsl 22')],
        calls=[(13676664, 'blx r7'), (13676688, 'bl sym.imp.memset'), (13676752, 'blx lr'), (13676852, 'bl sym.imp.objc_enumerationMutation'), (13676916, 'bl loc.imp.objc_msgSend'), (13676956, 'bl loc.imp.objc_msgSend'), (13676968, 'bl sym.imp.__modsi3'), (13677008, 'bl loc.imp.objc_msgSend'), (13677044, 'bl sym.imp.__aeabi_idiv'), (13677060, 'bl sym.imp.__aeabi_idiv'), (13677076, 'bl sym.imp.__aeabi_idiv'), (13677164, 'blx r3'), (13677268, 'blx ip'), (13677336, 'blx r2'), (13677428, 'blx r3')],
        branches=[(13676764, 'beq', 13677292), (13676844, 'beq', 13676856), (13677096, 'bne', 13677168), (13677112, 'bne', 13677168), (13677168, 'b', 13677172), (13677196, 'blo', 13676808), (13677288, 'bne', 13676808), (13677292, 'b', 13677296), (13677344, 'bne', 13677360), (13677356, 'b', 13677440)],
        semantics=('[ServerClient -[getAndRemoveAllRecieptDataForMacroPos:world:]] (imp 0x00d0afd0, 251w): -[getAndRemoveAllRecieptDataForMacroPos:world:] (0xd0afd0, 251w): arg struct macroPos {x=r2, y=r3}, world = stack fp+8. array=[NSMutableArray array]; fast-enumerate fillIndices@68: idx=[n unsignedIntValue]; W=[world worldWidthMacro]; x=(idx%(W*32))/32, y=(idx/(W*32))/32 (__modsi3 + __aeabi_idiv, lsl 5); if x==macroPos.x && y==macroPos.y -> [array addObject:n]. At end: if [array count]==0 return nil, else [fillIndices removeObjectsInArray:array] and return array..\n'),
    ),
    dict(
        name='svc_19',
        method='ServerClient -[hasEverRequestedHeartbeat]',
        types='c8@0:4',
        start=13678988,
        end=13679048,
        disasm='disasm_worldtileloader_svc_19.txt',
        base_add=13678996,
        base_literal=13679044,
        boundary='ARM.exidx end 0x00d0b9c8 (listing bound); next ObjC IMP 0x00d0b9c8 ServerClient -[setHasEverRequestedHeartbeat:]',
        selectors={},
        imports={},
        ivars={
                 0xd0b9c0: (17168136, 'OBJC_IVAR_$_ServerClient.hasEverRequestedHeartbeat', 57),
        },
        classes={},
        instructions=[(13678988, 'sub sp, sp, 8'), (13679044, 'eorseq r4, r5, r8, asr r1')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[hasEverRequestedHeartbeat]] (imp 0x00d0b98c, 15w): -[hasEverRequestedHeartbeat] (0xd0b98c, 15w): getter for hasEverRequestedHeartbeat@57 (char)..\n'),
    ),
    dict(
        name='svc_20',
        method='ServerClient -[initWithClientID:server:lightBlockIndex:lightBlockDatabase:]',
        types='@24@0:4@8@12i16@20',
        start=13658752,
        end=13662320,
        disasm='disasm_worldtileloader_svc_20.txt',
        base_add=13658768,
        base_literal=13662316,
        boundary='ARM.exidx end 0x00d07870 (listing bound); next ObjC IMP 0x00d07870 ServerClient -[clientReconnected]',
        selectors={
                 0xd077b0: (15238068, 'init'),
                 0xd077c4: (15238088, 'alloc'),
                 0xd077f8: (15238084, 'playerIsAdminWithAlias:'),
                 0xd07800: (15238080, 'objectForKey:'),
                 0xd07804: (15238076, 'playerInfoForPeerID:'),
                 0xd07814: (15238072, 'retain'),
                 0xd07818: (15238108, 'dataForKey:'),
                 0xd07820: (15238104, 'stringWithFormat:'),
                 0xd07838: (15238124, 'finishDecoding'),
                 0xd0783c: (15238120, 'autorelease'),
                 0xd07844: (15238116, 'decodeObjectForKey:'),
                 0xd07848: (15238112, 'initForReadingWithData:'),
                 0xd07850: (15238128, 'addIndexes:'),
                 0xd07854: (15238132, 'release'),
                 0xd0785c: (15238092, 'array'),
                 0xd07864: (15238096, 'numberWithInt:'),
                 0xd07868: (15238100, 'setObject:forKey:'),
        },
        imports={
                 0xd077ac: (17151900, 'objc_msgSendSuper2'),
                 0xd077c0: (17151904, 'objc_msgSend'),
                 0xd077fc: (16440888, '__CFConstantStringClassReference'),
                 0xd0781c: (16440904, '__CFConstantStringClassReference'),
                 0xd07840: (16440920, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd077b8: (17168052, 'OBJC_IVAR_$_ServerClient.worldIndicesContainingTamedAnimals', 72),
                 0xd077bc: (17168056, 'OBJC_IVAR_$_ServerClient.removalArraysToSend', 52),
                 0xd077cc: (17168060, 'OBJC_IVAR_$_ServerClient.updateUnreliableArraysToSend', 48),
                 0xd077d0: (17168064, 'OBJC_IVAR_$_ServerClient.creationDataUpdateArraysToSend', 44),
                 0xd077d4: (17168068, 'OBJC_IVAR_$_ServerClient.updateArraysToSend', 40),
                 0xd077d8: (17168072, 'OBJC_IVAR_$_ServerClient.creationArraysToSend', 36),
                 0xd077dc: (17168076, 'OBJC_IVAR_$_ServerClient.foundItemsList', 80),
                 0xd077e4: (17168080, 'OBJC_IVAR_$_ServerClient.requestedBlockIndices', 12),
                 0xd077e8: (17168084, 'OBJC_IVAR_$_ServerClient.wiredDynamicObjects', 32),
                 0xd077ec: (17168088, 'OBJC_IVAR_$_ServerClient.wiredBlocks', 28),
                 0xd077f0: (17168092, 'OBJC_IVAR_$_ServerClient.lightBlockIndex', 64),
                 0xd077f4: (17168096, 'OBJC_IVAR_$_ServerClient.isAdmin', 78),
                 0xd07808: (17168100, 'OBJC_IVAR_$_ServerClient.server', 8),
                 0xd0780c: (17168104, 'OBJC_IVAR_$_ServerClient.lightBlockDatabase', 88),
                 0xd07810: (17168108, 'OBJC_IVAR_$_ServerClient.clientID', 4),
                 0xd07828: (17168112, 'OBJC_IVAR_$_ServerClient.allLightBlockIndices', 84),
                 0xd0782c: (17168116, 'OBJC_IVAR_$_ServerClient.connected', 77),
                 0xd07830: (17168120, 'OBJC_IVAR_$_ServerClient.fillIndices', 68),
        },
        classes={
                 0xd077b4: (15253252, 'OBJC_CLASS_$_ServerClient'),
                 0xd077c8: (15251132, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0xd077e0: (15251128, 'OBJC_CLASS_$_NSMutableIndexSet'),
                 0xd07824: (15251144, 'OBJC_CLASS_$_NSString'),
                 0xd07834: (15251136, 'OBJC_CLASS_$_NSMutableArray'),
                 0xd0784c: (15251148, 'OBJC_CLASS_$_NSKeyedUnarchiver'),
                 0xd07860: (15251140, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(13658752, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13662316, 'eorseq sb, r5, ip, asr r0')],
        calls=[(13658860, 'blx r6'), (13659292, 'blx ip'), (13659424, 'blx r4'), (13659444, 'blx r3'), (13659476, 'blx r3'), (13659552, 'blx lr'), (13659568, 'blx r2'), (13659620, 'blx ip'), (13659636, 'blx r2'), (13659688, 'blx ip'), (13659704, 'blx r2'), (13659756, 'blx ip'), (13659772, 'blx r2'), (13659824, 'blx ip'), (13659840, 'blx r2'), (13659892, 'blx ip'), (13659908, 'blx r2'), (13659960, 'blx ip'), (13659976, 'blx r2'), (13660028, 'blx ip'), (13660044, 'blx r2'), (13660096, 'blx ip'), (13660112, 'blx r2'), (13660140, 'bl sym.imp.__wrap__Znwm'), (13660176, 'bl method.std::__1::__tree_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int______std::__1::__map_value_compare_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___true___std::__1::allocator_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.__tree_std::__1::__map_value_compare_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___true__const_'), (13660308, 'bl loc.imp.objc_msgSend'), (13660360, 'bl loc.imp.objc_msgSend'), (13660404, 'bl loc.imp.objc_msgSend'), (13660456, 'bl loc.imp.objc_msgSend'), (13660496, 'bl loc.imp.objc_msgSend'), (13660532, 'bl loc.imp.objc_msgSend'), (13660584, 'bl loc.imp.objc_msgSend'), (13660624, 'bl loc.imp.objc_msgSend'), (13660660, 'bl loc.imp.objc_msgSend'), (13660712, 'bl loc.imp.objc_msgSend'), (13660752, 'bl loc.imp.objc_msgSend'), (13660788, 'bl loc.imp.objc_msgSend'), (13660840, 'bl loc.imp.objc_msgSend'), (13660880, 'bl loc.imp.objc_msgSend'), (13660916, 'bl loc.imp.objc_msgSend'), (13660956, 'bl sym.imp.__wrap__Znwm'), (13660984, 'bl method.std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__tree_std::__1::less_unsigned_int__const_'), (13661100, 'bl method.std::__1::pair_std::__1::__tree_iterator_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int______std::__1::__tree_node_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int______void___int___bool__std::__1::__tree_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int______std::__1::__map_value_compare_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___true___std::__1::allocator_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________::__insert_unique_std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1.allocator_unsigned_int_______std::__1::pair_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____'), (13661456, 'blx r2'), (13661472, 'blx r2'), (13661544, 'blx ip'), (13661560, 'blx r2'), (13661656, 'blx ip'), (13661688, 'blx r3'), (13661864, 'blx lr'), (13661884, 'blx r3'), (13661912, 'blx r3'), (13661928, 'blx r2'), (13661944, 'blx r2'), (13661968, 'blx r2'), (13662056, 'blx r3'), (13662100, 'blx r2')],
        branches=[(13658888, 'bne', 13658904), (13658900, 'b', 13662112), (13660236, 'bge', 13661216), (13661212, 'b', 13660228), (13661708, 'beq', 13662104), (13661984, 'beq', 13662060)],
        semantics=('[ServerClient -[initWithClientID:server:lightBlockIndex:lightBlockDatabase:]] (imp 0x00d06a80, 892w): -[initWithClientID:server:lightBlockIndex:lightBlockDatabase:] (0xd06a80, 892w): [super init] (msgSendSuper2 {self, ServerClient}); clientID@4=[arg retain], server@8=arg (no retain), lightBlockDatabase@88=arg5, lightBlockIndex@64=arg4, isAdmin@78=[server playerIsAdminWithAlias:[pi objectForKey:@"alias"]] with pi=[server playerInfoForPeerID:clientID]; 4x [[NSMutableIndexSet alloc] init] -> wiredBlocks@28/wiredDynamicObjects@32/requestedBlockIndices@12/foundItemsList@80; 5x [[NSMutableDictionary alloc] init] -> the five *ArraysToSend queues; worldIndicesContainingTamedAnimals@72 = new(12B)+__tree ctor (bl 0xd0d0c4); loop i in 0..0x40: each of the 5 dicts gets [NSMutableArray array] under NSNumber(i) and map[i] = new(12B)+__tree<unsigned int> ctor (bl 0xd0cfe4 via __insert_unique bl 0xd0c520); allLightBlockIndices@84=[[NSMutableIndexSet alloc] init]; then if (data=[lightBlockDatabase dataForKey:[NSString stringWithFormat:@"%@_allIndexes", clientID]]) -> NSKeyedUnarchiver initForReadingWithData:, decodeObjectForKey:@"all", finishDecoding, addIndexes:, release. Returns self..\n'),
    ),
    dict(
        name='svc_21',
        method='ServerClient -[isAdmin]',
        types='c8@0:4',
        start=13678664,
        end=13678724,
        disasm='disasm_worldtileloader_svc_21.txt',
        base_add=13678672,
        base_literal=13678720,
        boundary='ARM.exidx end 0x00d0b884 (listing bound); next ObjC IMP 0x00d0b884 ServerClient -[setIsAdmin:]',
        selectors={},
        imports={},
        ivars={
                 0xd0b87c: (17168096, 'OBJC_IVAR_$_ServerClient.isAdmin', 78),
        },
        classes={},
        instructions=[(13678664, 'sub sp, sp, 8'), (13678720, 'mlaseq r5, ip, r2, r4')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[isAdmin]] (imp 0x00d0b848, 15w): -[isAdmin] (0xd0b848, 15w): getter for isAdmin@78 (char; set by init/reconnect from [server playerIsAdminWithAlias:], refreshable via setIsAdmin:)..\n'),
    ),
    dict(
        name='svc_22',
        method='ServerClient -[lightBlockIndex]',
        types='i8@0:4',
        start=13679264,
        end=13679324,
        disasm='disasm_worldtileloader_svc_22.txt',
        base_add=13679288,
        base_literal=13679320,
        boundary='ARM.exidx end 0x00d0badc (listing bound); next ObjC IMP 0x00d0badc ServerClient -[worldIndicesContainingTamedAnimals]',
        selectors={},
        imports={},
        ivars={
                 0xd0bad4: (17168092, 'OBJC_IVAR_$_ServerClient.lightBlockIndex', 64),
        },
        classes={},
        instructions=[(13679264, 'sub sp, sp, 8'), (13679320, 'eorseq r4, r5, r4, lsr r0')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[lightBlockIndex]] (imp 0x00d0baa0, 15w): -[lightBlockIndex] (0xd0baa0, 15w): getter for lightBlockIndex@64 (int)..\n'),
    ),
    dict(
        name='svc_23',
        method='ServerClient -[paused]',
        types='c8@0:4',
        start=13678468,
        end=13678528,
        disasm='disasm_worldtileloader_svc_23.txt',
        base_add=13678476,
        base_literal=13678524,
        boundary='ARM.exidx end 0x00d0b7c0 (listing bound); next ObjC IMP 0x00d0b7c0 ServerClient -[setPaused:]',
        selectors={},
        imports={},
        ivars={
                 0xd0b7b8: (17168128, 'OBJC_IVAR_$_ServerClient.paused', 76),
        },
        classes={},
        instructions=[(13678468, 'sub sp, sp, 8'), (13678524, 'eorseq r4, r5, r0, ror 6')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[paused]] (imp 0x00d0b784, 15w): -[paused] (0xd0b784, 15w): getter for paused@76 (char)..\n'),
    ),
    dict(
        name='svc_24',
        method='ServerClient -[removeBlockRequest:]',
        types='v12@0:4i8',
        start=13666740,
        end=13666920,
        disasm='disasm_worldtileloader_svc_24.txt',
        base_add=13666756,
        base_literal=13666916,
        boundary='ARM.exidx end 0x00d08ad8; body trimmed at the next IMP 0x00d08a68 ServerClient -[createIfNotCreatedForBlockRequest:]',
        selectors={
                 0xd08a58: (15238156, 'removeIndex:'),
        },
        imports={
                 0xd08a54: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd08a5c: (17168080, 'OBJC_IVAR_$_ServerClient.requestedBlockIndices', 12),
                 0xd08a60: (17168124, 'OBJC_IVAR_$_ServerClient.requestedBlockRequestTypes', 16),
        },
        classes={},
        instructions=[(13666740, 'push {fp, lr}'), (13666916, 'eorseq r7, r5, r8, lsr 2')],
        calls=[(13666812, 'bl method.std::__1::map_unsigned_int__unsigned_char__std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__unsigned_char_____.operator___unsigned_int_'), (13666888, 'blx r3')],
        branches=[],
        semantics=('[ServerClient -[removeBlockRequest:]] (imp 0x00d089b4, 45w): -[removeBlockRequest:] (0xd089b4, 45w): requestedBlockRequestTypes@16[i] = 0 (operator[] then strb 0); [requestedBlockIndices@12 removeIndex:i]. The counterpart cancel of requestForBlock:..\n'),
    ),
    dict(
        name='svc_25',
        method='ServerClient -[requestForBlock:]',
        types='v16@0:4{ClientMacroBlockRequest=iC[3C]}8',
        start=13665196,
        end=13665556,
        disasm='disasm_worldtileloader_svc_25.txt',
        base_add=13665212,
        base_literal=13665552,
        boundary='ARM.exidx end 0x00d08514 (listing bound); next ObjC IMP 0x00d088d4 ServerClient -[blockIsWired:]',
        selectors={
                 0xd08504: (15238148, 'addIndex:'),
        },
        imports={
                 0xd08500: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd084fc: (17168124, 'OBJC_IVAR_$_ServerClient.requestedBlockRequestTypes', 16),
                 0xd08508: (17168088, 'OBJC_IVAR_$_ServerClient.wiredBlocks', 28),
                 0xd0850c: (17168080, 'OBJC_IVAR_$_ServerClient.requestedBlockIndices', 12),
        },
        classes={},
        instructions=[(13665196, 'push {r4, r5, fp, lr}'), (13665552, 'eorseq r7, r5, r0, lsr r7')],
        calls=[(13665272, 'bl method.std::__1::map_unsigned_int__unsigned_char__std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__unsigned_char_____.operator___unsigned_int_'), (13665376, 'blx ip'), (13665444, 'bl method.std::__1::map_unsigned_int__unsigned_char__std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__unsigned_char_____.operator___unsigned_int_'), (13665520, 'blx r3')],
        branches=[(13665284, 'bne', 13665524)],
        semantics=('[ServerClient -[requestForBlock:]] (imp 0x00d083ac, 90w): -[requestForBlock:] (0xd083ac, 90w): arg struct ClientMacroBlockRequest {int index(r2); byte kind(r3)}. If map@16[index] != 0 -> early return; else [requestedBlockIndices@12 addIndex:index]; map[index] = (kind != 0) ? 1 : 2; [wiredBlocks@28 addIndex:index] (requesting a block also wires it to this client)..\n'),
    ),
    dict(
        name='svc_26',
        method='ServerClient -[requestedBlockIndices]',
        types='@8@0:4',
        start=13678400,
        end=13678468,
        disasm='disasm_worldtileloader_svc_26.txt',
        base_add=13678424,
        base_literal=13678464,
        boundary='ARM.exidx end 0x00d0b784 (listing bound); next ObjC IMP 0x00d0b784 ServerClient -[paused]',
        selectors={},
        imports={},
        ivars={
                 0xd0b77c: (17168080, 'OBJC_IVAR_$_ServerClient.requestedBlockIndices', 12),
        },
        classes={},
        instructions=[(13678400, 'sub sp, sp, 0xc'), (13678464, 'mlaseq r5, r4, r3, r4')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[requestedBlockIndices]] (imp 0x00d0b740, 17w): -[requestedBlockIndices] (0xd0b740, 17w): getter for requestedBlockIndices@12 (NSMutableIndexSet of pending block-stream requests)..\n'),
    ),
    dict(
        name='svc_27',
        method='ServerClient -[requestsHeartBeat]',
        types='c8@0:4',
        start=13678860,
        end=13678920,
        disasm='disasm_worldtileloader_svc_27.txt',
        base_add=13678868,
        base_literal=13678916,
        boundary='ARM.exidx end 0x00d0b948 (listing bound); next ObjC IMP 0x00d0b948 ServerClient -[setRequestsHeartBeat:]',
        selectors={},
        imports={},
        ivars={
                 0xd0b940: (17168132, 'OBJC_IVAR_$_ServerClient.requestsHeartBeat', 56),
        },
        classes={},
        instructions=[(13678860, 'sub sp, sp, 8'), (13678916, 'ldrsbteq r4, [r5], -r8')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[requestsHeartBeat]] (imp 0x00d0b90c, 15w): -[requestsHeartBeat] (0xd0b90c, 15w): getter for requestsHeartBeat@56 (char)..\n'),
    ),
    dict(
        name='svc_28',
        method='ServerClient -[saveLightBlockIndices]',
        types='v8@0:4',
        start=13677500,
        end=13678164,
        disasm='disasm_worldtileloader_svc_28.txt',
        base_add=13677516,
        base_literal=13678160,
        boundary='ARM.exidx end 0x00d0b654 (listing bound); next ObjC IMP 0x00d0b654 ServerClient -[setConnected:]',
        selectors={
                 0xd0b610: (15238132, 'release'),
                 0xd0b614: (15238240, 'setData:forKey:'),
                 0xd0b61c: (15238104, 'stringWithFormat:'),
                 0xd0b62c: (15238236, 'finishEncoding'),
                 0xd0b634: (15238232, 'encodeObject:forKey:'),
                 0xd0b63c: (15238228, 'initForWritingWithMutableData:'),
                 0xd0b640: (15238088, 'alloc'),
                 0xd0b648: (15238224, 'data'),
        },
        imports={
                 0xd0b60c: (17151904, 'objc_msgSend'),
                 0xd0b618: (16440904, '__CFConstantStringClassReference'),
                 0xd0b630: (16440920, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd0b620: (17168108, 'OBJC_IVAR_$_ServerClient.clientID', 4),
                 0xd0b628: (17168104, 'OBJC_IVAR_$_ServerClient.lightBlockDatabase', 88),
                 0xd0b638: (17168112, 'OBJC_IVAR_$_ServerClient.allLightBlockIndices', 84),
        },
        classes={
                 0xd0b624: (15251144, 'OBJC_CLASS_$_NSString'),
                 0xd0b644: (15251160, 'OBJC_CLASS_$_NSKeyedArchiver'),
                 0xd0b64c: (15251152, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(13677500, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13678160, 'eorseq r4, r5, r0, lsr 14')],
        calls=[(13677788, 'blx r3'), (13677824, 'blx r3'), (13677844, 'blx r3'), (13677904, 'blx ip'), (13677924, 'blx r2'), (13678012, 'blx r5'), (13678048, 'blx ip'), (13678080, 'blx r3')],
        branches=[],
        semantics=('[ServerClient -[saveLightBlockIndices]] (imp 0x00d0b3bc, 166w): -[saveLightBlockIndices] (0xd0b3bc, 166w): data=[NSMutableData data]; arch=[[NSKeyedArchiver alloc] initForWritingWithMutableData:data]; [arch encodeObject:allLightBlockIndices@84 forKey:<CFString "all">]; [arch finishEncoding]; [lightBlockDatabase@88 setData:data forKey:[NSString stringWithFormat:<CFString "%@_allIndexes">, clientID@4]]; [arch release]. Persistence mirror of svc_20\'s load..\n'),
    ),
    dict(
        name='svc_29',
        method='ServerClient -[sendAllObjectData]',
        types='v8@0:4',
        start=13672128,
        end=13675940,
        disasm='disasm_worldtileloader_svc_29.txt',
        base_add=13672144,
        base_literal=13675936,
        boundary='ARM.exidx end 0x00d0ada4 (listing bound); next ObjC IMP 0x00d0af10 ServerClient -[addFillRequest:]',
        selectors={
                 0xd0ad50: (15238164, 'count'),
                 0xd0ad54: (15238080, 'objectForKey:'),
                 0xd0ad58: (15238096, 'numberWithInt:'),
                 0xd0ad64: (15238140, 'removeAllObjects'),
                 0xd0ad68: (15238204, 'sendNetworkData:toPeers:reliable:'),
                 0xd0ad6c: (15238200, 'arrayWithObject:'),
                 0xd0ad7c: (15238196, 'appendData:'),
                 0xd0ad80: (15238192, 'gzipDeflate'),
                 0xd0ad84: (15238188, 'appendBytes:length:'),
                 0xd0ad88: (15238184, 'dataWithBytes:length:'),
        },
        imports={
                 0xd0ad4c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd0ad48: (17168116, 'OBJC_IVAR_$_ServerClient.connected', 77),
                 0xd0ad60: (17168072, 'OBJC_IVAR_$_ServerClient.creationArraysToSend', 36),
                 0xd0ad70: (17168108, 'OBJC_IVAR_$_ServerClient.clientID', 4),
                 0xd0ad78: (17168100, 'OBJC_IVAR_$_ServerClient.server', 8),
                 0xd0ad90: (17168064, 'OBJC_IVAR_$_ServerClient.creationDataUpdateArraysToSend', 44),
                 0xd0ad94: (17168068, 'OBJC_IVAR_$_ServerClient.updateArraysToSend', 40),
                 0xd0ad98: (17168060, 'OBJC_IVAR_$_ServerClient.updateUnreliableArraysToSend', 48),
                 0xd0ad9c: (17168056, 'OBJC_IVAR_$_ServerClient.removalArraysToSend', 52),
        },
        classes={
                 0xd0ad5c: (15251140, 'OBJC_CLASS_$_NSNumber'),
                 0xd0ad74: (15251156, 'OBJC_CLASS_$_NSArray'),
                 0xd0ad8c: (15251152, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(13672128, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13675936, 'eorseq r5, r5, ip, lsl ip')],
        calls=[(13672344, 'blx r4'), (13672376, 'blx r3'), (13672400, 'blx r2'), (13672520, 'blx r4'), (13672560, 'blx ip'), (13672568, 'bl 0xd0ada4'), (13672756, 'blx r2'), (13672784, 'blx r3'), (13672868, 'blx ip'), (13672916, 'blx lr'), (13672936, 'blx r2'), (13673064, 'blx r4'), (13673096, 'blx r3'), (13673120, 'blx r2'), (13673240, 'blx r4'), (13673280, 'blx ip'), (13673288, 'bl 0xd0ada4'), (13673476, 'blx r2'), (13673504, 'blx r3'), (13673588, 'blx ip'), (13673636, 'blx lr'), (13673656, 'blx r2'), (13673784, 'blx r4'), (13673816, 'blx r3'), (13673840, 'blx r2'), (13673960, 'blx r4'), (13674000, 'blx ip'), (13674008, 'bl 0xd0ada4'), (13674196, 'blx r2'), (13674224, 'blx r3'), (13674308, 'blx ip'), (13674356, 'blx lr'), (13674376, 'blx r2'), (13674504, 'blx r4'), (13674536, 'blx r3'), (13674560, 'blx r2'), (13674680, 'blx r4'), (13674720, 'blx ip'), (13674728, 'bl 0xd0ada4'), (13674916, 'blx r2'), (13674944, 'blx r3'), (13675028, 'blx ip'), (13675076, 'blx lr'), (13675096, 'blx r2'), (13675224, 'blx r4'), (13675256, 'blx r3'), (13675280, 'blx r2'), (13675400, 'blx r4'), (13675440, 'blx ip'), (13675448, 'bl 0xd0ada4'), (13675636, 'blx r2'), (13675664, 'blx r3'), (13675748, 'blx ip'), (13675796, 'blx lr'), (13675816, 'blx r2')],
        branches=[(13672188, 'bne', 13672196), (13672192, 'b', 13675840), (13672216, 'bge', 13675840), (13672408, 'bls', 13672940), (13673128, 'bls', 13673660), (13673848, 'bls', 13674380), (13674568, 'bls', 13675100), (13675288, 'bls', 13675820), (13675820, 'b', 13675824), (13675836, 'b', 13672208)],
        semantics=('[ServerClient -[sendAllObjectData]] (imp 0x00d09ec0, 953w): -[sendAllObjectData] (0xd09ec0, 953w): if (!connected@77) return; for i in 0..0x40, five scenes in fixed order: creationArraysToSend@36 (type byte 7), creationDataUpdateArraysToSend@44 (0x46), updateArraysToSend@40 (8, reliable=1), updateUnreliableArraysToSend@48 (8, reliable=0), removalArraysToSend@52 (9): a=[D objectForKey:NSNumber(i)]; if [a count]>0 -> pack=[NSMutableData dataWithBytes:&type length:1]; [pack appendBytes:&iByte length:1]; [pack appendData:[plistFromObject(a) gzipDeflate]] where plistFromObject = local helper 0xd0ada4 (NSPropertyListSerialization dataWithPropertyList:format:100 options:0 error:, @try/@catch); then [server@8 sendNetworkData:pack toPeers:[NSArray arrayWithObject:clientID@4] reliable:flag]; [a removeAllObjects]. 55 call sites executed 65x..\n'),
    ),
    dict(
        name='svc_30',
        method='ServerClient -[setConnected:]',
        types='v12@0:4c8',
        start=13678164,
        end=13678340,
        disasm='disasm_worldtileloader_svc_30.txt',
        base_add=13678180,
        base_literal=13678336,
        boundary='ARM.exidx end 0x00d0b704 (listing bound); next ObjC IMP 0x00d0b704 ServerClient -[connected]',
        selectors={
                 0xd0b6fc: (15238244, 'setPaused:'),
        },
        imports={
                 0xd0b6f8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd0b6f4: (17168116, 'OBJC_IVAR_$_ServerClient.connected', 77),
        },
        classes={},
        instructions=[(13678164, 'push {fp, lr}'), (13678336, 'eorseq r4, r5, r8, lsl 9')],
        calls=[(13678312, 'blx ip')],
        branches=[(13678248, 'bne', 13678316)],
        semantics=('[ServerClient -[setConnected:]] (imp 0x00d0b654, 44w): -[setConnected:] (0xd0b654, 44w): self->connected@77 = (char)value (strb); if the new value == 0 also [self setPaused:0] (disconnect clears the pause state via the setter)..\n'),
    ),
    dict(
        name='svc_31',
        method='ServerClient -[setHasEverRequestedHeartbeat:]',
        types='v12@0:4c8',
        start=13679048,
        end=13679116,
        disasm='disasm_worldtileloader_svc_31.txt',
        base_add=13679076,
        base_literal=13679112,
        boundary='ARM.exidx end 0x00d0baa0; body trimmed at the next IMP 0x00d0ba0c ServerClient -[timeSinceLastHeartbeatRequest]',
        selectors={},
        imports={},
        ivars={
                 0xd0ba04: (17168136, 'OBJC_IVAR_$_ServerClient.hasEverRequestedHeartbeat', 57),
        },
        classes={},
        instructions=[(13679048, 'sub sp, sp, 0xc'), (13679112, 'eorseq r4, r5, r8, lsl 2')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[setHasEverRequestedHeartbeat:]] (imp 0x00d0b9c8, 17w): -[setHasEverRequestedHeartbeat:] (0xd0b9c8, 17w): self->hasEverRequestedHeartbeat@57 = (char)value; strb guarded by dmb ish pair..\n'),
    ),
    dict(
        name='svc_32',
        method='ServerClient -[setIsAdmin:]',
        types='v12@0:4c8',
        start=13678724,
        end=13678792,
        disasm='disasm_worldtileloader_svc_32.txt',
        base_add=13678752,
        base_literal=13678788,
        boundary='ARM.exidx end 0x00d0b90c; body trimmed at the next IMP 0x00d0b8c8 ServerClient -[wiredDynamicObjects]',
        selectors={},
        imports={},
        ivars={
                 0xd0b8c0: (17168096, 'OBJC_IVAR_$_ServerClient.isAdmin', 78),
        },
        classes={},
        instructions=[(13678724, 'sub sp, sp, 0xc'), (13678788, 'eorseq r4, r5, ip, asr 4')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[setIsAdmin:]] (imp 0x00d0b884, 17w): -[setIsAdmin:] (0xd0b884, 17w): self->isAdmin@78 = (char)value; dmb ish pair..\n'),
    ),
    dict(
        name='svc_33',
        method='ServerClient -[setPaused:]',
        types='v12@0:4c8',
        start=13678528,
        end=13678596,
        disasm='disasm_worldtileloader_svc_33.txt',
        base_add=13678556,
        base_literal=13678592,
        boundary='ARM.exidx end 0x00d0b848; body trimmed at the next IMP 0x00d0b804 ServerClient -[clientID]',
        selectors={},
        imports={},
        ivars={
                 0xd0b7fc: (17168128, 'OBJC_IVAR_$_ServerClient.paused', 76),
        },
        classes={},
        instructions=[(13678528, 'sub sp, sp, 0xc'), (13678592, 'eorseq r4, r5, r0, lsl r3')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[setPaused:]] (imp 0x00d0b7c0, 17w): -[setPaused:] (0xd0b7c0, 17w): self->paused@76 = (char)value; dmb ish pair..\n'),
    ),
    dict(
        name='svc_34',
        method='ServerClient -[setRequestsHeartBeat:]',
        types='v12@0:4c8',
        start=13678920,
        end=13678988,
        disasm='disasm_worldtileloader_svc_34.txt',
        base_add=13678948,
        base_literal=13678984,
        boundary='ARM.exidx end 0x00d0b98c (listing bound); next ObjC IMP 0x00d0b98c ServerClient -[hasEverRequestedHeartbeat]',
        selectors={},
        imports={},
        ivars={
                 0xd0b984: (17168132, 'OBJC_IVAR_$_ServerClient.requestsHeartBeat', 56),
        },
        classes={},
        instructions=[(13678920, 'sub sp, sp, 0xc'), (13678984, 'eorseq r4, r5, r8, lsl 3')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[setRequestsHeartBeat:]] (imp 0x00d0b948, 17w): -[setRequestsHeartBeat:] (0xd0b948, 17w): self->requestsHeartBeat@56 = (char)value; dmb ish pair..\n'),
    ),
    dict(
        name='svc_35',
        method='ServerClient -[setTimeSinceLastHeartbeatRequest:]',
        types='v12@0:4f8',
        start=13679188,
        end=13679264,
        disasm='disasm_worldtileloader_svc_35.txt',
        base_add=13679220,
        base_literal=13679260,
        boundary='ARM.exidx end 0x00d0baa0 (listing bound); next ObjC IMP 0x00d0baa0 ServerClient -[lightBlockIndex]',
        selectors={},
        imports={},
        ivars={
                 0xd0ba98: (17168140, 'OBJC_IVAR_$_ServerClient.timeSinceLastHeartbeatRequest', 60),
        },
        classes={},
        instructions=[(13679188, 'sub sp, sp, 0xc'), (13679260, 'eorseq r4, r5, r8, ror r0')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[setTimeSinceLastHeartbeatRequest:]] (imp 0x00d0ba54, 19w): -[setTimeSinceLastHeartbeatRequest:] (0xd0ba54, 19w): self->timeSinceLastHeartbeatRequest@60 = float; arg moved vmov s0,r2 -> vstr [sp] -> str after offset-cell resolution; dmb ish pair..\n'),
    ),
    dict(
        name='svc_36',
        method='ServerClient -[setWorldIndicesContainingTamedAnimals:]',
        types='v12@0:4^{map<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *, std::__1::less<unsigned int>, std::__1::allocator<std::__1::pair<const unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *> > >={__tree<std::__1::pair<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *>, std::__1::__map_value_compare<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *, std::__1::less<unsigned int>, true>, std::__1::allocator<std::__1::pair<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *> > >=^{__tree_node<std::__1::pair<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *>, void *>}{__compressed_pair<std::__1::__tree_end_node<std::__1::__tree_node_base<void *> *>, std::__1::allocator<std::__1::__tree_node<std::__1::pair<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *>, void *> > >={__tree_end_node<std::__1::__tree_node_base<void *> *>=^{__tree_node_base<void *>}}}{__compressed_pair<unsigned long, std::__1::__map_value_compare<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *, std::__1::less<unsigned int>, true> >=L}}}8',
        start=13679392,
        end=13679460,
        disasm='disasm_worldtileloader_svc_36.txt',
        base_add=13679420,
        base_literal=13679456,
        boundary='ARM.exidx end 0x00d0bbec; body trimmed at the next IMP 0x00d0bb64 ServerClient -[foundItemsList]',
        selectors={},
        imports={},
        ivars={
                 0xd0bb5c: (17168052, 'OBJC_IVAR_$_ServerClient.worldIndicesContainingTamedAnimals', 72),
        },
        classes={},
        instructions=[(13679392, 'sub sp, sp, 0xc'), (13679456, 'ldrhteq r3, [r5], -r0')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[setWorldIndicesContainingTamedAnimals:]] (imp 0x00d0bb20, 17w): -[setWorldIndicesContainingTamedAnimals:] (0xd0bb20, 17w): self->worldIndicesContainingTamedAnimals@72 = pointer (raw store of the map<uint,set<uint>*>* arg); dmb ish pair. Ownership not retained here..\n'),
    ),
    dict(
        name='svc_37',
        method='ServerClient -[timeSinceLastHeartbeatRequest]',
        types='f8@0:4',
        start=13679116,
        end=13679188,
        disasm='disasm_worldtileloader_svc_37.txt',
        base_add=13679140,
        base_literal=13679184,
        boundary='ARM.exidx end 0x00d0baa0; body trimmed at the next IMP 0x00d0ba54 ServerClient -[setTimeSinceLastHeartbeatRequest:]',
        selectors={},
        imports={},
        ivars={
                 0xd0ba4c: (17168140, 'OBJC_IVAR_$_ServerClient.timeSinceLastHeartbeatRequest', 60),
        },
        classes={},
        instructions=[(13679116, 'sub sp, sp, 0xc'), (13679184, 'eorseq r4, r5, r8, asr 1')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[timeSinceLastHeartbeatRequest]] (imp 0x00d0ba0c, 18w): -[timeSinceLastHeartbeatRequest] (0xd0ba0c, 18w): getter for timeSinceLastHeartbeatRequest@60 (float); loaded via dmb ish + vldr s0,[sp] + vmov r0,s0..\n'),
    ),
    dict(
        name='svc_38',
        method='ServerClient -[unwireDynamicObject:]',
        types='v12@0:4I8',
        start=13667360,
        end=13667468,
        disasm='disasm_worldtileloader_svc_38.txt',
        base_add=13667376,
        base_literal=13667464,
        boundary='ARM.exidx end 0x00d08c8c (listing bound); next ObjC IMP 0x00d08c8c ServerClient -[addCreationObjectDataToSend:ofType:objectID:]',
        selectors={
                 0xd08c80: (15238156, 'removeIndex:'),
        },
        imports={
                 0xd08c7c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd08c84: (17168084, 'OBJC_IVAR_$_ServerClient.wiredDynamicObjects', 32),
        },
        classes={},
        instructions=[(13667360, 'push {r4, sl, fp, lr}'), (13667464, 'ldrhteq r6, [r5], -ip')],
        calls=[(13667440, 'blx ip')],
        branches=[],
        semantics=('[ServerClient -[unwireDynamicObject:]] (imp 0x00d08c20, 27w): -[unwireDynamicObject:] (0xd08c20, 27w): [self->wiredDynamicObjects@32 removeIndex:objID (unsigned int)]..\n'),
    ),
    dict(
        name='svc_39',
        method='ServerClient -[wireDynamicObject:]',
        types='v12@0:4I8',
        start=13667252,
        end=13667360,
        disasm='disasm_worldtileloader_svc_39.txt',
        base_add=13667268,
        base_literal=13667356,
        boundary='ARM.exidx end 0x00d08c20 (listing bound); next ObjC IMP 0x00d08c20 ServerClient -[unwireDynamicObject:]',
        selectors={
                 0xd08c14: (15238148, 'addIndex:'),
        },
        imports={
                 0xd08c10: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd08c18: (17168084, 'OBJC_IVAR_$_ServerClient.wiredDynamicObjects', 32),
        },
        classes={},
        instructions=[(13667252, 'push {r4, sl, fp, lr}'), (13667356, 'eorseq r6, r5, r8, lsr 30')],
        calls=[(13667332, 'blx ip')],
        branches=[],
        semantics=('[ServerClient -[wireDynamicObject:]] (imp 0x00d08bb4, 27w): -[wireDynamicObject:] (0xd08bb4, 27w): [self->wiredDynamicObjects@32 addIndex:objID (unsigned int)] -- marks a dynamic object as kept in sync for this client..\n'),
    ),
    dict(
        name='svc_40',
        method='ServerClient -[wiredDynamicObjects]',
        types='@8@0:4',
        start=13678792,
        end=13678860,
        disasm='disasm_worldtileloader_svc_40.txt',
        base_add=13678816,
        base_literal=13678856,
        boundary='ARM.exidx end 0x00d0b90c (listing bound); next ObjC IMP 0x00d0b90c ServerClient -[requestsHeartBeat]',
        selectors={},
        imports={},
        ivars={
                 0xd0b904: (17168084, 'OBJC_IVAR_$_ServerClient.wiredDynamicObjects', 32),
        },
        classes={},
        instructions=[(13678792, 'sub sp, sp, 0xc'), (13678856, 'eorseq r4, r5, ip, lsl 4')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[wiredDynamicObjects]] (imp 0x00d0b8c8, 17w): -[wiredDynamicObjects] (0xd0b8c8, 17w): getter for wiredDynamicObjects@32 (NSMutableIndexSet of wired dynamic-object type IDs)..\n'),
    ),
    dict(
        name='svc_41',
        method='ServerClient -[worldIndicesContainingTamedAnimals]',
        types='^{map<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *, std::__1::less<unsigned int>, std::__1::allocator<std::__1::pair<const unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *> > >={__tree<std::__1::pair<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *>, std::__1::__map_value_compare<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *, std::__1::less<unsigned int>, true>, std::__1::allocator<std::__1::pair<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *> > >=^{__tree_node<std::__1::pair<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *>, void *>}{__compressed_pair<std::__1::__tree_end_node<std::__1::__tree_node_base<void *> *>, std::__1::allocator<std::__1::__tree_node<std::__1::pair<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *>, void *> > >={__tree_end_node<std::__1::__tree_node_base<void *> *>=^{__tree_node_base<void *>}}}{__compressed_pair<unsigned long, std::__1::__map_value_compare<unsigned int, std::__1::set<unsigned int, std::__1::less<unsigned int>, std::__1::allocator<unsigned int> > *, std::__1::less<unsigned int>, true> >=L}}}8@0:4',
        start=13679324,
        end=13679392,
        disasm='disasm_worldtileloader_svc_41.txt',
        base_add=13679348,
        base_literal=13679388,
        boundary='ARM.exidx end 0x00d0bbec; body trimmed at the next IMP 0x00d0bb20 ServerClient -[setWorldIndicesContainingTamedAnimals:]',
        selectors={},
        imports={},
        ivars={
                 0xd0bb18: (17168052, 'OBJC_IVAR_$_ServerClient.worldIndicesContainingTamedAnimals', 72),
        },
        classes={},
        instructions=[(13679324, 'sub sp, sp, 0xc'), (13679388, 'ldrshteq r3, [r5], -r8')],
        calls=[],
        branches=[],
        semantics=('[ServerClient -[worldIndicesContainingTamedAnimals]] (imp 0x00d0badc, 17w): -[worldIndicesContainingTamedAnimals] (0xd0badc, 17w): getter for worldIndicesContainingTamedAnimals@72 (returns the map<unsigned int, set<unsigned int>*>* pointer as stored; ownership not transferred)..\n'),
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
        'batch': 'ServerClient (E150): the per-client server state; 42 bodies',
        'claim': ('the ServerClient state (five send queues, heartbeat, light database)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'serverclient.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale serverclient.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
