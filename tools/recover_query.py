#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld query/accessor smalls (E34).

The DynamicWorld query/accessor smalls: the NPC and harmable-object lookups,
the blockhead ID lookup, the local/disconnected merge, the local net ID, the
path-user collector, the rail-name notification and the lights-ready check:
1 body, 1133 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/QUERY_ACCESS.md for the prose and boundaries.
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
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_': 0x008bcb78,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.objectTypeMayHaveArtificalLight_int_': 0x00903420,
}

SPECS = [
    dict(
        name='wtl_npcwithid_',
        method='DynamicWorld -[npcWithID:]',
        types='@16@0:4Q8',
        start=9380852,
        end=9381424,
        disasm='disasm_worldtileloader_npcwithid_.txt',
        base_add=9380868,
        base_literal=9381420,
        boundary='ARM.exidx end 0x008f2630 (listing bound); next ObjC IMP 0x008f2630 DynamicWorld -[harmableDynamicObjectWithID:]',
        selectors={},
        imports={},
        ivars={
                 0x8f2610: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8f261c: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9380852, 'push {r4, r5, r6, sl, fp, lr}'), (9380904, 'cmp r0, 8'), (9380988, 'add r1, r2, r1'), (9381016, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9381116, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9381148, 'ldr r2, [r2, r3]'), (9381420, 'rsbseq sp, r6, r8, ror 13')],
        calls=[(9381016, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9381116, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9381236, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9381336, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_')],
        branches=[(9380908, 'bge', 9381372), (9381024, 'beq', 9381132), (9381128, 'b', 9381380), (9381244, 'beq', 9381352), (9381348, 'b', 9381380), (9381352, 'b', 9381356), (9381368, 'b', 9380900)],
        semantics=("npcWithID: resolves an NPC by uniqueID across the world registries. Prologue 0x008f23f4 (frame 0x60; base 0x105faf4).\nFamily gate: `if (arg >= 8) return nil` (@0x8f2428).\nLookup 1: the **0x00E4AA1C jump table** (cell 0x8f2614, the 8-arm family table) selects the ffffe54c slice (`movw r1, 0xc; mul` 12-byte striding @0x8f2434-0x8f247c); `__count_unique(u64)` (@0x8f2498): hit -> `operator[](u64 const&)` (@0x8f24fc) returns the object (@0x8f2500).\nLookup 2: miss -> the **ffffe550 map segment** with the same 12-byte striding (`__count_unique` from @0x8f250c) — the two-registry lookup shared with E31's loadStandardDynamicObjectOfType:atPos:.\n"),
    ),
    dict(
        name='wtl_harmabledynamicobjectw',
        method='DynamicWorld -[harmableDynamicObjectWithID:]',
        types='@16@0:4Q8',
        start=9381424,
        end=9382052,
        disasm='disasm_worldtileloader_harmabledynamicobjectwithid_.txt',
        base_add=9381440,
        base_literal=9382048,
        boundary='ARM.exidx end 0x008f28a4 (listing bound); next ObjC IMP 0x008f28a4 DynamicWorld -[npcExistsAtPos:ignoreNPC:]',
        selectors={
                 0x8f2888: (15217060, 'npcWithID:'),
                 0x8f2890: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8f2894: (15217056, 'allBlockheadsIncludingNet'),
                 0x8f2898: (15216160, 'uniqueID'),
        },
        imports={
                 0x8f288c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9381424, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9381508, 'beq 0x8f2694'), (9381552, 'ldr r4, [0x008f2890]'), (9381620, 'blx r2'), (9381812, 'ldr r2, [0x008f2898]'), (9382048, 'rsbseq sp, r6, ip, lsr 9')],
        calls=[(9381488, 'bl loc.imp.objc_msgSend'), (9381620, 'blx r2'), (9381644, 'bl sym.imp.memset'), (9381692, 'blx lr'), (9381792, 'bl sym.imp.objc_enumerationMutation'), (9381828, 'bl loc.imp.objc_msgSend'), (9381976, 'blx ip')],
        branches=[(9381508, 'beq', 9381524), (9381520, 'b', 9382012), (9381704, 'beq', 9382000), (9381784, 'beq', 9381796), (9381856, 'bne', 9381876), (9381860, 'b', 9381864), (9381872, 'b', 9382012), (9381876, 'b', 9381880), (9381904, 'blo', 9381748), (9381996, 'bne', 9381748), (9382000, 'b', 9382004)],
        semantics=('harmableDynamicObjectWithID: resolves a harmable dynamic object by ID. Prologue 0x008f2630 (frame 0xe8; base 0x105faf4).\nPre: the ffe236b0 check (@0x8f2648-0x8f2684) gates the scan.\nEnumerate: a collection (cell chain ffe231ec/ffe236ac @0x8f26b0-0x8f26cc) is enumerated (`blx r2` @0x8f26f4 walk + mutation guard @0x8f27a0); per element `[obj uniqueID]` (ffe2332c @0x8f27b4) is read for the match.\n'),
    ),
    dict(
        name='wtl_blockheadwithidincludi',
        method='DynamicWorld -[blockheadWithIDIncludingNet:]',
        types='@16@0:4Q8',
        start=9409324,
        end=9409900,
        disasm='disasm_worldtileloader_blockheadwithidincludingnet_.txt',
        base_add=9409340,
        base_literal=9409896,
        boundary='ARM.exidx end 0x008f956c (listing bound); next ObjC IMP 0x008f956c DynamicWorld -[connectionToServerLost]',
        selectors={
                 0x8f9558: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8f955c: (15217056, 'allBlockheadsIncludingNet'),
                 0x8f9560: (15216160, 'uniqueID'),
        },
        imports={
                 0x8f9554: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9409324, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9409392, 'ldr r0, [0x008f955c]'), (9409472, 'blx r6'), (9409664, 'ldr r2, [0x008f9560]'), (9409704, 'cmp r0, 0'), (9409896, 'ldrhteq r6, [r6], -0x70')],
        calls=[(9409472, 'blx r6'), (9409496, 'bl sym.imp.memset'), (9409544, 'blx lr'), (9409644, 'bl sym.imp.objc_enumerationMutation'), (9409680, 'bl loc.imp.objc_msgSend'), (9409828, 'blx ip')],
        branches=[(9409556, 'beq', 9409852), (9409636, 'beq', 9409648), (9409708, 'bne', 9409728), (9409712, 'b', 9409716), (9409724, 'b', 9409864), (9409728, 'b', 9409732), (9409756, 'blo', 9409600), (9409848, 'bne', 9409600), (9409852, 'b', 9409856)],
        semantics=('blockheadWithIDIncludingNet: resolves a blockhead ID including network blockheads. Prologue 0x008f932c (frame 0xe0; base 0x105faf4).\nEnumerate: the collection behind ffe236ac (@0x8f9370) is enumerated (@0x8f93c0 walk); per element `[bh uniqueID]` (ffe2332c @0x8f9480) compared via the **eor/orr 64-bit equality** (@0x8f949c-0x8f94a8: `eor r1, r1, r3; eor r0, r0, r2; orr r0, r0, r1`); a match returns (@0x8f94ac+); the enumeration loop continues (@0x8f94c8).\n'),
    ),
    dict(
        name='wtl_localanddisconnectedcl',
        method='DynamicWorld -[localAndDisconnectedClientBlockheads]',
        types='@8@0:4',
        start=9398264,
        end=9398612,
        disasm='disasm_worldtileloader_localanddisconnectedclientblockheads.txt',
        base_add=9398280,
        base_literal=9398608,
        boundary='ARM.exidx end 0x008f6954 (listing bound); next ObjC IMP 0x008f6954 DynamicWorld -[clientPickupRequest:count:clientID:blockheadRequesterUniqueID:]',
        selectors={
                 0x8f6940: (15215864, 'count'),
                 0x8f6948: (15217052, 'arrayByAddingObjectsFromArray:'),
        },
        imports={
                 0x8f693c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f6938: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8f6944: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8f694c: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
        },
        classes={},
        instructions=[(9398264, 'push {fp, lr}'), (9398328, 'beq 0x8f6860'), (9398364, 'b 0x8f692c'), (9398412, 'ldr r1, [r2]'), (9398496, 'ldr r3, [0x008f6944]'), (9398608, 'rsbseq sb, r6, r4, ror 5')],
        calls=[(9398428, 'blx r2'), (9398564, 'blx r3')],
        branches=[(9398328, 'beq', 9398368), (9398364, 'b', 9398572), (9398436, 'bne', 9398476), (9398472, 'b', 9398572)],
        semantics=('localAndDisconnectedClientBlockheads merges the local and disconnected-client blockheads. Prologue 0x008f67f8 (frame 0x20; base 0x105faf4).\nBranch: `self.client (ffffe518) != 0` (@0x8f6810-0x8f6838) -> returns the **ffffe4f8 blockheads** directly (@0x8f683c-0x8f685c).\nServer: otherwise the **ffffe4f0** collection is consulted via ffe23204/ffe236a8 (@0x8f686c-0x8f68e0) and merged with ffffe4f8 — the combined collection.\n'),
    ),
    dict(
        name='wtl_localnetid',
        method='DynamicWorld -[localNetID]',
        types='@8@0:4',
        start=9397608,
        end=9397912,
        disasm='disasm_worldtileloader_localnetid.txt',
        base_add=9397624,
        base_literal=9397908,
        boundary='ARM.exidx end 0x008f6698 (listing bound); next ObjC IMP 0x008f6698 DynamicWorld -[allBlockheadsIncludingNet]',
        selectors={
                 0x8f6690: (15215984, 'localPlayerID'),
        },
        imports={
                 0x8f6688: (16333352, '__CFConstantStringClassReference'),
                 0x8f668c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f6680: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8f6684: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
        },
        classes={},
        instructions=[(9397608, 'push {fp, lr}'), (9397672, 'beq 0x8f65f4'), (9397736, 'blx r2'), (9397784, 'beq 0x8f6664'), (9397808, 'ldr r3, [0x008f6684]'), (9397908, 'rsbseq sb, r6, r4, ror r5')],
        calls=[(9397736, 'blx r2'), (9397848, 'blx r2')],
        branches=[(9397672, 'beq', 9397748), (9397744, 'b', 9397876), (9397784, 'beq', 9397860), (9397856, 'b', 9397876)],
        semantics=('localNetID resolves the local network ID. Prologue 0x008f6568 (frame 0x20; base 0x105faf4).\nBranch: client (ffffe518, @0x8f6580-0x8f65a8) -> the ffe2327c call on the client (@0x8f65b8-0x8f65e8); otherwise the **ffffe51c** registry slot with ffe2327c (@0x8f65f8-0x8f6630) — the local-net-ID getter.\n'),
    ),
    dict(
        name='wtl_pathusers',
        method='DynamicWorld -[pathUsers]',
        types='@8@0:4',
        start=9428844,
        end=9430180,
        disasm='disasm_worldtileloader_pathusers.txt',
        base_add=9428860,
        base_literal=9429628,
        boundary='ARM.exidx end 0x008fe4a4 (listing bound); next ObjC IMP 0x008fe280 DynamicWorld -[railOrStationNameChanged]',
        selectors={
                 0x8fe260: (15216144, 'array'),
                 0x8fe26c: (15217192, 'localAndDisconnectedClientBlockheads'),
                 0x8fe270: (15217052, 'arrayByAddingObjectsFromArray:'),
                 0x8fe274: (15217188, 'controlIsLocal'),
                 0x8fe278: (15216008, 'addObject:'),
                 0x8fe49c: (15216852, 'railOrStationNameChanged'),
        },
        imports={
                 0x8fe268: (17151904, 'objc_msgSend'),
                 0x8fe498: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8fe264: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8fe494: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={
                 0x8fe258: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9428844, 'push {fp, lr}'), (9428976, 'ldr r0, [r0, 0x1d4]'), (9429212, 'beq 0x8fe1cc'), (9429388, 'blx r3'), (9429396, 'strb r0, [sp, 0x4b]'), (9429436, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9430176, 'rsbseq r1, r6, ip, asr r8')],
        calls=[(9428924, 'bl loc.imp.objc_msgSend'), (9429308, 'blx r2'), (9429388, 'blx r3'), (9429436, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9429492, 'blx r2'), (9429572, 'blx r3'), (9430076, 'blx r2'), (9430112, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9429212, 'beq', 9429452), (9429320, 'beq', 9429400), (9429400, 'b', 9429404), (9429448, 'b', 9429128), (9429508, 'bne', 9429524), (9429520, 'b', 9429580), (9429680, 'bge', 9430148), (9429988, 'beq', 9430128), (9430124, 'b', 9429904), (9430128, 'b', 9430132), (9430144, 'b', 9429672)],
        semantics=("pathUsers collects the world's path users. Prologue 0x008fdf6c (frame 0x100; base 0x105faf4).\nSet build: `[[class ffe2aeb0 alloc] init]` + the ffe2331c call (@0x8fdf94-0x8fdfbc) creates the result set; the found byte at sp+0x4b initialised (@0x8fdf8c-0x8fdf90).\nWalk: the **ffffe54c member's +0x1d4 path-user slice** (`ldr r0, [r0, 0x1d4]` @0x8fdff0) is tree-walked (the eor/tst guard @0x8fe0c8-0x8fe0dc); per node the **ffe23730 check** (cell 0x8fe274, @0x8fe0ec) runs with the node payload ([node+0x10]+8 @0x8fe114-0x8fe120); a hit collects via the **ffe23294 addObject: call** (cell 0x8fe278, @0x8fe18c) and sets the found byte (@0x8fe194); `__tree_next` advances (@0x8fe1bc); the ffe23734 call closes (@0x8fe1d8). The +0x1d4 slice matches E31's ridable cascade probe.\n"),
    ),
    dict(
        name='wtl_railorstationnamechang',
        method='DynamicWorld -[railOrStationNameChanged]',
        types='v8@0:4',
        start=9429632,
        end=9430180,
        disasm='disasm_worldtileloader_railorstationnamechanged.txt',
        base_add=9429648,
        base_literal=9430176,
        boundary='ARM.exidx end 0x008fe4a4 (listing bound); next ObjC IMP 0x008fe4a4 DynamicWorld -[reloadDynamicObjectStaticGemometryForMacroTile:]',
        selectors={
                 0x8fe49c: (15216852, 'railOrStationNameChanged'),
        },
        imports={
                 0x8fe498: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8fe494: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9429632, 'push {fp, lr}'), (9429676, 'cmp r0, 4'), (9429732, 'add r1, r1, r1, lsl 1'), (9429988, 'beq 0x8fe470'), (9430076, 'blx r2'), (9430176, 'rsbseq r1, r6, ip, asr r8')],
        calls=[(9430076, 'blx r2'), (9430112, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9429680, 'bge', 9430148), (9429988, 'beq', 9430128), (9430124, 'b', 9429904), (9430128, 'b', 9430132), (9430144, 'b', 9429672)],
        semantics=('railOrStationNameChanged notifies the rail/station name change. Prologue 0x008fe280 (frame 0xd8; base 0x105faf4). Argument: the index (r1).\nGate: `if (arg >= 4) return` (@0x8fe2ac-0x8fe2b0).\nWalk: the **0x00E4AA0C jump table** (cell 0x8fe48c, 4 arms) selects the ffffe54c slice (`add r1, r1, r1, lsl 1` <<2 12-byte striding @0x8fe2e4); the tree walk (guards @0x8fe3d0-0x8fe3e4): per node the **ffe235e0 call** (cell 0x8fe49c, @0x8fe3f4) runs with the node payload ([node+0x10]+8 @0x8fe41c-0x8fe428).\n'),
    ),
    dict(
        name='wtl_haslightstoadd',
        method='DynamicWorld -[hasLightsToAdd]',
        types='c8@0:4',
        start=9450680,
        end=9450900,
        disasm='disasm_worldtileloader_haslightstoadd.txt',
        base_add=9450696,
        base_literal=9450896,
        boundary='ARM.exidx end 0x00903594 (listing bound); next ObjC IMP 0x00903594 DynamicWorld -[loadedCountOfObjectsOfType:]',
        selectors={},
        imports={},
        ivars={
                 0x90358c: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9450680, 'push {fp, lr}'), (9450724, 'cmp r0, 0x41'), (9450736, 'bl sym.objectTypeMayHaveArtificalLight_int_'), (9450788, 'add r0, r1, r0'), (9450844, 'strb r0, [fp, -0x11]'), (9450896, 'rsbseq ip, r5, r4, lsr 12')],
        calls=[(9450736, 'bl sym.objectTypeMayHaveArtificalLight_int_')],
        branches=[(9450728, 'bge', 9450872), (9450748, 'beq', 9450852), (9450836, 'beq', 9450852), (9450848, 'b', 9450880), (9450852, 'b', 9450856), (9450868, 'b', 9450720)],
        semantics=("hasLightsToAdd answers whether light contributions remain to add. Prologue 0x009034b8 (frame 0x30; base 0x105faf4). Argument: the object type (r0).\nGate: `if (objectType >= 0x41) return false` (@0x9034e4); **`objectTypeMayHaveArtificalLight(int)`** (C call @0x9034f0) must hold (@0x9034fc).\nLoop: `for i in 0..0x41` (@0x90356c-0x903574): the **ffffe550 map's 12-byte segments** (`movw r0, 0xc; mul` @0x903500-0x903524) have their count at +8 checked (`ldr r0, [r0+8]` @0x903538-0x90354c): a non-zero count sets the true flag (@0x903558-0x90355c).\n"),
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
        'batch': 'DynamicWorld query/accessor smalls (E34): npcWithID:, harmableDynamicObjectWithID:, blockheadWithIDIncludingNet:, localAndDisconnectedClientBlockheads, localNetID, pathUsers, railOrStationNameChanged and hasLightsToAdd; 8 bodies',
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
                        default=NATIVE / 'query_access.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale query_access.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
