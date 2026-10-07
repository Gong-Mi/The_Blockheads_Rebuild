#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld block-load/accessor smalls: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 605 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/BLOCK_LOAD_ACCESS.md for the prose and boundaries.
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
    'bl 0x8b1db0': 0x008b1db0,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.objectTypeIsInteractionObject_int_': 0x008bcacc,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_removeobjectduetorepai',
        method='DynamicWorld -[removeObjectDueToRepair:]',
        types='v12@0:4@8',
        start=9460524,
        end=9461200,
        disasm='disasm_worldtileloader_removeobjectduetorepair_.txt',
        base_add=9460540,
        base_literal=9461196,
        boundary='ARM.exidx end 0x00905dd0 (listing bound); next ObjC IMP 0x00905dd0 DynamicWorld -[doRepairForTileAtPos:]',
        selectors={
                 0x905da4: (15216168, 'objectType'),
                 0x905da8: (15217364, 'freeblockCreationItemType'),
                 0x905dac: (15216884, 'removeStandardObject:'),
                 0x905db0: (15216012, 'pos'),
                 0x905db8: (15217368, 'freeBlockCreationDataA'),
                 0x905dbc: (15217372, 'freeBlockCreationDataB'),
                 0x905dc0: (15217376, 'freeBlockCreationSaveDict'),
                 0x905dc4: (15216388, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x905dc8: (15217028, 'remove:'),
        },
        imports={
                 0x905da0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x905d9c: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
        },
        classes={},
        instructions=[(9460524, 'push {r4, r5, fp, lr}'), (9460548, 'ldr lr, [0x00905d9c]'), (9460644, 'bl sym.objectTypeIsInteractionObject_int_'), (9460704, 'blx r3'), (9460728, 'ldr r3, [0x00905da8]'), (9460872, 'bl loc.imp.objc_msgSend_stret'), (9461196, 'ldrhteq sb, [r5], -0xf0')],
        calls=[(9460640, 'blx r2'), (9460644, 'bl sym.objectTypeIsInteractionObject_int_'), (9460704, 'blx r3'), (9460780, 'blx ip'), (9460800, 'blx r2'), (9460872, 'bl loc.imp.objc_msgSend_stret'), (9460908, 'bl sym.imp.memset'), (9460936, 'bl loc.imp.objc_msgSend'), (9460968, 'bl loc.imp.objc_msgSend'), (9461000, 'bl loc.imp.objc_msgSend'), (9461032, 'bl loc.imp.objc_msgSend'), (9461132, 'bl loc.imp.objc_msgSend')],
        branches=[(9460592, 'bne', 9460600), (9460596, 'b', 9461140), (9460656, 'beq', 9460712), (9460708, 'b', 9461140), (9460808, 'beq', 9461136), (9460856, 'beq', 9460880), (9460876, 'b', 9460912), (9461136, 'b', 9461140)],
        semantics=('removeObjectDueToRepair: removes an object because it was repaired. Prologue 0x00905b2c (frame 0x78; base 0x105faf4). Argument: the object.\nGate: the **ffffe51c server registry** (cell 0x905d9c, @0x905b44-0x905b70) must be set.\nDispatch: `[obj objectType]` (ffe23334 @0x905b84) -> **`objectTypeIsInteractionObject(int)`** (C call @0x905ba4):\n  - interaction objects: the **ffe23690 call** with argument 0 (@0x905bc4-0x905be0, `movw r2, 0`) - notify;\n  - otherwise: the ffe237e0/ffe23600 pickup-family calls (@0x905bf8-0x905c2c) + the object position via the ffe23298 stret read (@0x905c88) + the worldIndex resolution + the removal walk (continuation from 0x905cb4).\n'),
    ),
    dict(
        name='wtl_clientblockheadsreciev',
        method='DynamicWorld -[clientBlockheadsRecievedForPlayerID:data:]',
        types='v16@0:4@8@12',
        start=9417064,
        end=9417352,
        disasm='disasm_worldtileloader_clientblockheadsrecievedforplayerid_data.txt',
        base_add=9417080,
        base_literal=9417348,
        boundary='ARM.exidx end 0x008fb288 (listing bound); next ObjC IMP 0x008fb288 DynamicWorld -[clientBlockheadInventoryRecievedForPlayerID:blockheadID:data:]',
        selectors={
                 0x8fb26c: (15215988, 'gzipInflate'),
                 0x8fb270: (15216092, 'setData:forKey:'),
                 0x8fb27c: (15215816, 'stringWithFormat:'),
        },
        imports={
                 0x8fb268: (17151904, 'objc_msgSend'),
                 0x8fb278: (16333032, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8fb274: (17162240, 'OBJC_IVAR_$_DynamicWorld.worldDatabase', 32),
        },
        classes={
                 0x8fb280: (15247792, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(9417064, 'push {r4, r5, r6, sl, fp, lr}'), (9417132, 'bl 0x8b1db0'), (9417152, 'beq 0x8fb260'), (9417172, 'ldr r3, [0x008fb270]'), (9417248, 'ldr lr, [sp, 0x10]'), (9417348, 'rsbseq r4, r6, r4, ror sb')],
        calls=[(9417128, 'blx lr'), (9417132, 'bl 0x8b1db0'), (9417256, 'blx lr'), (9417304, 'blx lr')],
        branches=[(9417152, 'beq', 9417312)],
        semantics=('clientBlockheadsRecievedForPlayerID:data: applies received client-blockhead data. Prologue 0x008fb168 (frame 0x40; base 0x105faf4).\nParse: the shared parser **0x008b1db0** (the E21 loadAnyBlockheads parse helper) runs on the payload (`bl 0x8b1db0` @0x8fb1ac); the empty result exits (@0x8fb1bc-0x8fb1c0).\nApply: the **ffffe50c** slot + the 0xfff33df4 string + the ffe2aebc/ffe231d4 creation calls (@0x8fb1d4-0x8fb220) materialise the blockheads for the player.\n'),
    ),
    dict(
        name='wtl_portalisbeingremovedat',
        method='DynamicWorld -[portalIsBeingRemovedAtPos:]',
        types='v16@0:4{?=ii}8',
        start=9449276,
        end=9449492,
        disasm='disasm_worldtileloader_portalisbeingremovedatpos_.txt',
        base_add=9449292,
        base_literal=9449488,
        boundary='ARM.exidx end 0x00903014 (listing bound); next ObjC IMP 0x00903014 DynamicWorld -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        selectors={
                 0x903000: (15216224, 'removeIndex:'),
        },
        imports={
                 0x902ffc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x903004: (17162204, 'OBJC_IVAR_$_DynamicWorld.portalPositions', 7332),
                 0x90300c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9449276, 'push {fp, lr}'), (9449336, 'ldr r0, [r0, r1]'), (9449400, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9449444, 'mov r1, r3'), (9449488, 'rsbseq ip, r5, r0, lsr 23')],
        calls=[(9449400, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9449456, 'blx r3')],
        branches=[],
        semantics=('portalIsBeingRemovedAtPos: answers whether a portal is being removed at a position. Prologue 0x00902f3c (frame 0x30; base 0x105faf4).\nResolve: the **ffffe4e8 world-struct chain** (cell 0x903004, @0x902f64-0x902f78) + `worldIndexAtWorldPos(intpair, World*)` (@0x902fb8); the ffe2336c call (@0x903000) answers (@0x902fe4) - a direct query, tail-returns.\n'),
    ),
    dict(
        name='wtl_loadedcountofobjectsof',
        method='DynamicWorld -[loadedCountOfObjectsOfType:]',
        types='i12@0:4i8',
        start=9450900,
        end=9451100,
        disasm='disasm_worldtileloader_loadedcountofobjectsoftype_.txt',
        base_add=9450912,
        base_literal=9451096,
        boundary='ARM.exidx end 0x0090365c (listing bound); next ObjC IMP 0x0090365c DynamicWorld -[poleItemTaken:]',
        selectors={},
        imports={},
        ivars={
                 0x903650: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x903654: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9450900, 'push {r4, lr}'), (9450916, 'movw ip, 0xc'), (9450968, 'add r0, r1, r0'), (9451096, 'rsbseq ip, r5, ip, asr 10')],
        calls=[],
        branches=[],
        semantics=("loadedCountOfObjectsOfType: returns the count of loaded objects of a type. Prologue 0x00903594 (frame 0x34; base 0x105faf4). Argument: the type (r0).\nCount: the **ffffe550 map's 12-byte segment** (`movw ip, 0xc; mul r0, r0, ip` @0x9035a4-0x9035d8) is addressed; the segment's count is returned (the ffffe54c reference cell 0x903654 accompanies the ffffe550 cell 0x903650).\n"),
    ),
    dict(
        name='wtl_loadgatherblockatpos_',
        method='DynamicWorld -[loadGatherBlockAtPos:]',
        types='v16@0:4{?=ii}8',
        start=9393456,
        end=9393640,
        disasm='disasm_worldtileloader_loadgatherblockatpos_.txt',
        base_add=9393472,
        base_literal=9393636,
        boundary='ARM.exidx end 0x008f55e8 (listing bound); next ObjC IMP 0x008f55e8 DynamicWorld -[gatherBlockAtPos:]',
        selectors={
                 0x8f55dc: (15216804, 'loadStandardDynamicObjectOfType:atPos:'),
        },
        imports={},
        ivars={
                 0x8f55d8: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
        },
        classes={},
        instructions=[(9393456, 'push {r4, sl, fp, lr}'), (9393524, 'beq 0x8f557c'), (9393532, 'movw r0, 0x1a'), (9393584, 'str ip, [lr]'), (9393636, 'rsbseq sl, r6, ip, lsr 11')],
        calls=[(9393608, 'bl loc.imp.objc_msgSend')],
        branches=[(9393524, 'beq', 9393532), (9393528, 'b', 9393616)],
        semantics=('loadGatherBlockAtPos: creates/loads the gather block at a position. Prologue 0x008f5530 (frame 0x30; base 0x105faf4).\nGate: client (ffffe518, @0x8f5548-0x8f5574) != 0 -> return.\nCreate: the type **0x1a (26)** (`movw r0, 0x1a` @0x8f557c) + the ffe235b0 creation call (@0x8f5594-0x8f55b0) with the pos argument - the gather block (types 25/26 are the gather family).\n'),
    ),
    dict(
        name='wtl_isclient',
        method='DynamicWorld -[isClient]',
        types='c8@0:4',
        start=9397440,
        end=9397608,
        disasm='disasm_worldtileloader_isclient.txt',
        base_add=9397448,
        base_literal=9397520,
        boundary='ARM.exidx end 0x008f6568 (listing bound); next ObjC IMP 0x008f6514 DynamicWorld -[isServer]',
        selectors={},
        imports={},
        ivars={
                 0x8f650c: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8f6560: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
        },
        classes={},
        instructions=[(9397440, 'sub sp, sp, 8'), (9397488, 'cmp r0, r3'), (9397500, 'and r0, r0, 1'), (9397604, 'ldrsbteq sb, [r6], -0x50')],
        calls=[],
        branches=[],
        semantics=('isClient answers whether this world is a client. Prologue 0x008f64c0 (frame 0; base 0x105faf4).\nBody: `self.client (ffffe518) != nil` -> the boolean (`cmp r0, 0; movne r0, 1; and r0, r0, 1; sxtb` @0x8f64f0-0x8f6500). Confirms ffffe518 = the client slot.\n'),
    ),
    dict(
        name='wtl_netblockheads',
        method='DynamicWorld -[netBlockheads]',
        types='@8@0:4',
        start=9398124,
        end=9398264,
        disasm='disasm_worldtileloader_netblockheads.txt',
        base_add=9398140,
        base_literal=9398260,
        boundary='ARM.exidx end 0x008f67f8 (listing bound); next ObjC IMP 0x008f67f8 DynamicWorld -[localAndDisconnectedClientBlockheads]',
        selectors={
                 0x8f67e8: (15217052, 'arrayByAddingObjectsFromArray:'),
        },
        imports={
                 0x8f67e4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f67ec: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8f67f0: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
        },
        classes={},
        instructions=[(9398124, 'push {r4, sl, fp, lr}'), (9398152, 'ldr ip, [0x008f67e8]'), (9398232, 'blx r3'), (9398260, 'rsbseq sb, r6, r0, ror r3')],
        calls=[(9398232, 'blx r3')],
        branches=[],
        semantics=('netBlockheads returns the net blockheads collection. Prologue 0x008f676c (frame 0x18; base 0x105faf4).\nBody: the **ffffe4f0** and **ffffe4f4** collections merged via the ffe236a8 call (@0x8f6788-0x8f67d8) - the net blockhead getter.\n'),
    ),
    dict(
        name='wtl_gatherblockatpos_',
        method='DynamicWorld -[gatherBlockAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9393640,
        end=9393752,
        disasm='disasm_worldtileloader_gatherblockatpos_.txt',
        base_add=9393700,
        base_literal=9393748,
        boundary='ARM.exidx end 0x008f5658 (listing bound); next ObjC IMP 0x008f5658 DynamicWorld -[teleportBlockhead:toWorkbench:]',
        selectors={
                 0x8f5650: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9393640, 'push {fp, lr}'), (9393652, 'movw ip, 0x1a'), (9393692, 'ldr r1, [0x008f5650]'), (9393728, 'str ip, [sp, 4]'), (9393748, 'rsbseq sl, r6, r8, asr 9')],
        calls=[(9393732, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('gatherBlockAtPos: returns the gather block at a position. Prologue 0x008f55e8 (frame 0x28; base 0x105faf4).\nBody: the type **0x1a (26)** (`movw ip, 0x1a` @0x8f55f4, `mov r2, 0x1a` @0x8f563c) + the **ffe235f0 lookup call** (@0x8f561c-0x8f5644) - the gather-block resolver (tail-returns).\n'),
    ),
    dict(
        name='wtl_isserver',
        method='DynamicWorld -[isServer]',
        types='c8@0:4',
        start=9397524,
        end=9397608,
        disasm='disasm_worldtileloader_isserver.txt',
        base_add=9397532,
        base_literal=9397604,
        boundary='ARM.exidx end 0x008f6568 (listing bound); next ObjC IMP 0x008f6568 DynamicWorld -[localNetID]',
        selectors={},
        imports={},
        ivars={
                 0x8f6560: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
        },
        classes={},
        instructions=[(9397524, 'sub sp, sp, 8'), (9397572, 'cmp r0, r3'), (9397588, 'sxtb r0, r0'), (9397604, 'ldrsbteq sb, [r6], -0x50')],
        calls=[],
        branches=[],
        semantics=("isServer answers whether this world is a server. Prologue 0x008f6514 (frame 0; base 0x105faf4).\nBody: `self.server (ffffe51c) != nil` -> the boolean (`cmp r0, 0; movne r0, 1` @0x8f6544-0x8f6554). Confirms ffffe51c = the server slot - the pair with isClient's ffffe518.\n"),
    ),
    dict(
        name='wtl_allblockheadsincluding',
        method='DynamicWorld -[allBlockheadsIncludingNet]',
        types='@8@0:4',
        start=9397912,
        end=9398124,
        disasm='disasm_worldtileloader_allblockheadsincludingnet.txt',
        base_add=9397928,
        base_literal=9398120,
        boundary='ARM.exidx end 0x008f676c (listing bound); next ObjC IMP 0x008f676c DynamicWorld -[netBlockheads]',
        selectors={
                 0x8f6758: (15217052, 'arrayByAddingObjectsFromArray:'),
        },
        imports={
                 0x8f6754: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f675c: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8f6760: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8f6764: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
        },
        classes={},
        instructions=[(9397912, 'push {r4, r5, fp, lr}'), (9398104, 'invalid'), (9398012, 'ldr r2, [ip]'), (9398120, 'rsbseq sb, r6, r4, asr 8')],
        calls=[(9398040, 'blx r3'), (9398088, 'blx ip')],
        branches=[],
        semantics=('allBlockheadsIncludingNet merges all blockhead collections. Prologue 0x008f6698 (frame 0x28; base 0x105faf4).\nBody: the **ffffe4f0 + ffffe4f4 + ffffe4f8** collections merged via the ffe236a8 call (@0x8f6758-0x8f66fc) - the full blockhead collection getter.\n'),
    ),
    dict(
        name='wtl_portalpositions',
        method='DynamicWorld -[portalPositions]',
        types='@8@0:4',
        start=9428652,
        end=9428712,
        disasm='disasm_worldtileloader_portalpositions.txt',
        base_add=9428660,
        base_literal=9428708,
        boundary='ARM.exidx end 0x008fdee8 (listing bound); next ObjC IMP 0x008fdee8 DynamicWorld -[findAndSubtractAllPowerUpTo:forUser:]',
        selectors={},
        imports={},
        ivars={
                 0x8fdee0: (17162204, 'OBJC_IVAR_$_DynamicWorld.portalPositions', 7332),
        },
        classes={},
        instructions=[(9428652, 'sub sp, sp, 8'), (9428704, 'invalid'), (9428700, 'bx lr'), (9428708, 'rsbseq r1, r6, r8, lsr ip')],
        calls=[],
        branches=[],
        semantics=("portalPositions returns the world's portal positions. Prologue 0x008fdeac (frame 0; base 0x105faf4).\nBody: the **ffffe4e8 world-struct member** is read and returned directly (@0x8fdee0-0x8fdedc) - the portal-positions getter (the same ffffe4e8 chain E35's portalIsBeingRemovedAtPos: uses).\n"),
    ),
    dict(
        name='wtl_blockheads',
        method='DynamicWorld -[blockheads]',
        types='@8@0:4',
        start=9449216,
        end=9449276,
        disasm='disasm_worldtileloader_blockheads.txt',
        base_add=9449224,
        base_literal=9449272,
        boundary='ARM.exidx end 0x00902f3c (listing bound); next ObjC IMP 0x00902f3c DynamicWorld -[portalIsBeingRemovedAtPos:]',
        selectors={},
        imports={},
        ivars={
                 0x902f34: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
        },
        classes={},
        instructions=[(9449216, 'sub sp, sp, 8'), (9449268, 'invalid'), (9449264, 'bx lr'), (9449272, 'rsbseq ip, r5, r4, ror 23')],
        calls=[],
        branches=[],
        semantics=("blockheads returns the local blockheads collection. Prologue 0x00902f00 (frame 0; base 0x105faf4).\nBody: the **ffffe4f8 blockheads member** is read and returned directly (@0x902f34-0x902f30) - the blockheads getter pair with E27/E29's ffffe4f8 uses.\n"),
    ),
    dict(
        name='wtl_connectiontoserverlost',
        method='DynamicWorld -[connectionToServerLost]',
        types='v8@0:4',
        start=9409900,
        end=9409920,
        disasm='disasm_worldtileloader_connectiontoserverlost.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x008f9580 (listing bound); next ObjC IMP 0x008f9580 DynamicWorld -[setPaused:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9409900, 'sub sp, sp, 8'), (9409916, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('connectionToServerLost is a no-op connection-loss notification. Prologue 0x008f956c (frame 0).\nBody: prologue, empty body, return (@0x8f9578-0x8f957c) - 5 words; the notification is handled elsewhere (or the stub is reserved).\n'),
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
        'batch': 'DynamicWorld block-load/accessor smalls (E35): removeObjectDueToRepair:, clientBlockheadsRecievedForPlayerID:data:, portalIsBeingRemovedAtPos:, loadedCountOfObjectsOfType:, loadGatherBlockAtPos:, isClient, netBlockheads, gatherBlockAtPos:, isServer, allBlockheadsIncludingNet, portalPositions, blockheads and connectionToServerLost; 13 bodies',
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
                        default=NATIVE / 'block_load_access.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale block_load_access.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
