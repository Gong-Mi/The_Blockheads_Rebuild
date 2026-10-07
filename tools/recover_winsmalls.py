#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the Window class and the SteamTrain small accessors: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 1185 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WINDOW_SMALLS.md for the prose and boundaries.
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
    'bl 0xc98e5c': 0x00c98e5c,
    'bl 0xc99338': 0x00c99338,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
}

SPECS = [
    dict(
        name='win_ctor_placed',
        method='Window -[initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:]',
        types='@40@0:4@8@12{?=ii}16@24i28@32@36',
        start=13207200,
        end=13207876,
        disasm='disasm_worldtileloader_win_ctor_placed.txt',
        base_add=13207216,
        base_literal=13207872,
        boundary='ARM.exidx end 0x00c98944 (listing bound); next ObjC IMP 0x00c98944 Window -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xc98920: (15235504, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0xc98930: (15235512, 'objectForKey:'),
                 0xc98938: (15235508, 'retain'),
                 0xc9893c: (15235516, 'initSubDerivedItems'),
        },
        imports={
                 0xc98928: (16396120, '__CFConstantStringClassReference'),
                 0xc9892c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xc98924: (17167348, 'OBJC_IVAR_$_Window.itemType', 56),
                 0xc98934: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xc98918: (15253204, 'OBJC_CLASS_$_Window'),
        },
        instructions=[(13207200, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13207400, 'bl loc.imp.objc_msgSendSuper2'), (13207424, 'cmp r1, r0'), (13207476, 'str r3, [r1]'), (13207536, 'blx r2'), (13207872, 'eorseq r7, ip, ip, lsr r4')],
        calls=[(13207400, 'bl loc.imp.objc_msgSendSuper2'), (13207536, 'blx r2'), (13207624, 'blx r3'), (13207724, 'blx lr'), (13207740, 'blx r2'), (13207808, 'blx r2')],
        branches=[(13207428, 'bne', 13207444), (13207440, 'b', 13207820), (13207488, 'beq', 13207564), (13207560, 'b', 13207768), (13207636, 'beq', 13207764), (13207764, 'b', 13207768)],
        semantics=('[Window initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:] (imp 0x00c986a0, 169w): super2 (@0xc98768) then the nil-r check (`cmp r1, 0; bne` @0xc98780): on success the fffff900 cell + the ffffc8ac/ffffbcac cells store the placed state (str @0xc987b4) and the ffe27ec0 chain runs the post-placement hook (@0xc987f0 blx r2 = the cache insert callback). The `type:` argument (r4) is threaded through.\n'),
    ),
    dict(
        name='win_ctor_net',
        method='Window -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=13208432,
        end=13209180,
        disasm='disasm_worldtileloader_win_ctor_net.txt',
        base_add=13208448,
        base_literal=13209176,
        boundary='ARM.exidx end 0x00c98e5c (listing bound); next ObjC IMP 0x00c98e80 Window -[getSaveDict]',
        selectors={
                 0xc98e20: (15235528, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0xc98e2c: (15235536, 'length'),
                 0xc98e34: (15235532, 'getBytes:length:'),
                 0xc98e3c: (15235508, 'retain'),
                 0xc98e44: (15235512, 'objectForKey:'),
                 0xc98e48: (15235544, 'gzipInflate'),
                 0xc98e50: (15235540, 'subdataWithRange:'),
                 0xc98e54: (15235516, 'initSubDerivedItems'),
        },
        imports={
                 0xc98e1c: (17151900, 'objc_msgSendSuper2'),
                 0xc98e28: (17151904, 'objc_msgSend'),
                 0xc98e40: (16396120, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xc98e30: (17167348, 'OBJC_IVAR_$_Window.itemType', 56),
                 0xc98e38: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xc98e24: (15253204, 'OBJC_CLASS_$_Window'),
        },
        instructions=[(13208432, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13208584, 'blx r6'), (13208660, 'movw lr, 0x20'), (13208768, 'bls 0xc98ddc'), (13209176, 'eorseq r6, ip, ip, ror 30')],
        calls=[(13208584, 'blx r6'), (13208716, 'blx lr'), (13208760, 'blx r3'), (13208832, 'bl loc.imp.objc_msgSend'), (13208900, 'bl loc.imp.objc_msgSend'), (13208924, 'blx r2'), (13208928, 'bl 0xc98e5c'), (13209012, 'blx r3'), (13209028, 'blx r2'), (13209092, 'blx r2')],
        branches=[(13208612, 'bne', 13208628), (13208624, 'b', 13209104), (13208768, 'bls', 13209052)],
        semantics=('[Window initWithWorld:dynamicWorld:cache:netData:] (imp 0x00c98b70, 187w): super2-shaped entry (`blx r6` via ffffbca8 @0xc98c08) + nil gate (@0xc98c20); the netData length chain reads a **0x20 (32)-byte record** (`movw lr, 0x20` @0xc98c54, blx @0xc98c8c) and length-checks (`cmp r0, 0x20; bls` @0xc98cbc-0xc98cc0) before decoding the window-specific fields via the ffffc8ac/ffffbcac/fffff900 cells.\n'),
    ),
    dict(
        name='win_creationdata',
        method='Window -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=13209748,
        end=13210424,
        disasm='disasm_worldtileloader_win_creationdata.txt',
        base_add=13209764,
        base_literal=13210420,
        boundary='ARM.exidx end 0x00c99338 (listing bound); next ObjC IMP 0x00c994a4 Window -[dealloc]',
        selectors={
                 0xc99304: (15235564, 'dynamicObjectNetData'),
                 0xc99310: (15235572, 'dictionary'),
                 0xc99318: (15235568, 'dataWithBytes:length:'),
                 0xc99328: (15235556, 'setObject:forKey:'),
                 0xc9932c: (15235580, 'appendData:'),
                 0xc99330: (15235576, 'gzipDeflate'),
        },
        imports={
                 0xc9930c: (17151904, 'objc_msgSend'),
                 0xc99324: (16396120, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xc99308: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xc99320: (17167348, 'OBJC_IVAR_$_Window.itemType', 56),
        },
        classes={
                 0xc99314: (15250796, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0xc9931c: (15250792, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(13209748, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13209876, 'bl sym.imp.memset'), (13210036, 'bl sym.imp.memcpy'), (13210060, 'strh r0, [fp, -0x30]'), (13210420, 'eorseq r6, ip, r8, asr 20')],
        calls=[(13209840, 'bl loc.imp.objc_msgSend_stret'), (13209876, 'bl sym.imp.memset'), (13210036, 'bl sym.imp.memcpy'), (13210100, 'blx lr'), (13210136, 'blx r3'), (13210260, 'blx ip'), (13210268, 'bl 0xc99338'), (13210328, 'blx lr'), (13210356, 'blx r3')],
        branches=[(13209824, 'beq', 13209848), (13209844, 'b', 13209880), (13210172, 'beq', 13210264)],
        semantics=('[Window creationNetDataForClient:] (imp 0x00c99094, 169w): the creation record - nil path zero-fills a **0x18 (24)-byte stret** (`movw r2, 0x18` + memset @0xc990fc-0xc99114); the live path reads the state via the ffffc8ac/ffffbcac/fffff900 cells, **memcpy**s the **0x18**-byte record (@0xc99164-0xc991b4, `movw r5, 0x20` frame arg) and stores the halfword field (`strh` @0xc991cc); the ffe27f00/ffe2ba74/ffe2ba78 call chain packs the client record.\n'),
    ),
    dict(
        name='win_updatenet',
        method='Window -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=13209664,
        end=13209748,
        disasm='disasm_worldtileloader_win_updatenet.txt',
        base_add=13209680,
        base_literal=13209744,
        boundary='ARM.exidx end 0x00c99094 (listing bound); next ObjC IMP 0x00c99094 Window -[creationNetDataForClient:]',
        selectors={
                 0xc9908c: (15235560, 'creationNetDataForClient:'),
        },
        imports={
                 0xc99088: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(13209664, 'push {fp, lr}'), (13209724, 'blx ip'), (13209744, 'mlaseq ip, ip, sl, r6')],
        calls=[(13209724, 'blx ip')],
        branches=[],
        semantics=('[Window updateNetDataForClient:] (imp 0x00c99040, 21w): the thin forwarder - ffffbcac + the ffe27ef4 chain, one `blx ip` (@0xc9907c) then return: the window update delegates to the shared net-data update.\n'),
    ),
    dict(
        name='win_draw',
        method='Window -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=13210984,
        end=13211536,
        disasm='disasm_worldtileloader_win_draw.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00c99790 (listing bound); next ObjC IMP 0x00c99790 Window -[occupiesBackgroundContents]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13210984, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13210992, 'sub sp, sp, 0x110'), (13210996, 'bic sp, sp, 0xf'), (13211528, 'sub sp, fp, 0x18'), (13211532, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        calls=[],
        branches=[],
        semantics=('[Window draw:...] (imp 0x00c99568, roster 0x00c99568..0x00c99790): the roster region is **pure argument-frame marshalling**: push + `sub sp, 0x110` + `bic sp, sp, 0xf` (**16-byte frame alignment** - the two `_GLKMatrix4` structs by value: types line `v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152`) then the fp->sp shuffle of all 8 arguments + the 5 int camera params into the aligned frame, ending pop. No in-region call: the draw continuation (the shared draw helper already covered in the E25/E41 draw passes) sits at the roster seam - flagged as boundary rather than invented.\n'),
    ),
    dict(
        name='win_setneedsremoved',
        method='Window -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=13206840,
        end=13207200,
        disasm='disasm_worldtileloader_win_setneedsremoved.txt',
        base_add=13206856,
        base_literal=13207196,
        boundary='ARM.exidx end 0x00c986a0 (listing bound); next ObjC IMP 0x00c986a0 Window -[initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:]',
        selectors={
                 0xc98680: (15235496, 'setNeedsRemoved:'),
                 0xc98698: (15235500, 'updateSunLightRemovedForTile:atPos:world:'),
        },
        imports={
                 0xc9867c: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xc98690: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xc98694: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xc98684: (15253204, 'OBJC_CLASS_$_Window'),
                 0xc98688: (15250784, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(13206840, 'push {r4, r5, fp, lr}'), (13206952, 'blx lr'), (13206964, 'beq 0xc98674'), (13207052, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13207152, 'bl loc.imp.objc_msgSend'), (13207196, 'eorseq r7, ip, r4, lsr 11')],
        calls=[(13206952, 'blx lr'), (13207052, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13207152, 'bl loc.imp.objc_msgSend')],
        branches=[(13206964, 'beq', 13207156)],
        semantics=("[Window setNeedsRemoved:] (imp 0x00c98538, 90w): runs the super-class update (`blx lr` via the ffffbca8 cell @0xc985a8 with the sxtb'd flag), then the flag gate `ldrsb; cmp 0; beq` (@0xc985ac-0xc985b4): on removal the ffffc89c/ffffc8a0 chain reads the window's tile position and calls **tileAtWorldPositionLoaded** (@0xc9860c) + the ffe27eb8 caller's objc_msgSend (@0xc98670) - the window notifies its tile on removal (same family as gb_setneedsremoved's light-glow reload).\n"),
    ),
    dict(
        name='win_dealloc',
        method='Window -[dealloc]',
        types='v8@0:4',
        start=13210788,
        end=13210984,
        disasm='disasm_worldtileloader_win_dealloc.txt',
        base_add=13210804,
        base_literal=13210980,
        boundary='ARM.exidx end 0x00c99568 (listing bound); next ObjC IMP 0x00c99568 Window -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0xc99550: (15235588, 'dealloc'),
                 0xc9955c: (15235584, 'release'),
        },
        imports={
                 0xc9954c: (17151900, 'objc_msgSendSuper2'),
                 0xc99558: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xc99560: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xc99554: (15253204, 'OBJC_CLASS_$_Window'),
        },
        instructions=[(13210788, 'push {r4, r5, r6, r7, fp, lr}'), (13210904, 'blx r5'), (13210944, 'blx r2'), (13210980, 'eorseq r6, ip, r8, lsr r6')],
        calls=[(13210904, 'blx r5'), (13210944, 'blx r2')],
        branches=[],
        semantics=('[Window dealloc] (imp 0x00c994a4, 49w): the ivar-cell teardown - ffffbca8/ffffbcac/ffffc8ac cells + the ffe27f0c/ffe27f10 chain, one `blx r5` (@0xc99518) then the super dealloc `blx r2` (@0xc99540) - no branches.\n'),
    ),
    dict(
        name='win_initsubderived',
        method='Window -[initSubDerivedItems]',
        types='v8@0:4',
        start=13206732,
        end=13206840,
        disasm='disasm_worldtileloader_win_initsubderived.txt',
        base_add=13206788,
        base_literal=13206836,
        boundary='ARM.exidx end 0x00c98538 (listing bound); next ObjC IMP 0x00c984e0 Window -[objectType]',
        selectors={},
        imports={},
        ivars={
                 0xc98530: (17167348, 'OBJC_IVAR_$_Window.itemType', 56),
        },
        classes={},
        instructions=[(13206732, 'sub sp, sp, 8'), (13206752, 'sub sp, sp, 8'), (13206836, 'eorseq r7, ip, r8, ror 11')],
        calls=[],
        branches=[],
        semantics=("[Window initSubDerivedItems] (imp 0x00c984cc, 27w): **empty body** - sub r8/sp-8, add sp+8, bx lr: the window derives nothing (contrast the torch/lamp sub-derived items of the E36 family). The roster neighbor at 0x00c984e0 is the tiny `movw r2, 0x1f; mov r0, r2` returner (returns **31 = the window's item type**, matching the pinned window=0x1f type code from the accessor family).\n"),
    ),
    dict(
        name='win_fbitemtype',
        method='Window -[freeblockCreationItemType]',
        types='i8@0:4',
        start=13206780,
        end=13206840,
        disasm='disasm_worldtileloader_win_fbitemtype.txt',
        base_add=13206788,
        base_literal=13206836,
        boundary='ARM.exidx end 0x00c98538 (listing bound); next ObjC IMP 0x00c98538 Window -[setNeedsRemoved:]',
        selectors={},
        imports={},
        ivars={
                 0xc98530: (17167348, 'OBJC_IVAR_$_Window.itemType', 56),
        },
        classes={},
        instructions=[(13206780, 'sub sp, sp, 8'), (13206816, 'add r0, r0, r1'), (13206836, 'eorseq r7, ip, r8, ror 11')],
        calls=[],
        branches=[],
        semantics=("[Window freeblockCreationItemType] (imp 0x00c984fc, 15w): the ivar-cell pattern - `ldr r2, [..]; add r2, pc, r2` builds the ivar-offset base (0xfffff900 cell + the class cell 0x3c75e8), then `ldr r1, [r2]; add r0, r0, r1; ldr r0, [r0]` reads the ivar - the window's creation item type comes from an ivar (the cell-id oracle of the window class).\n"),
    ),
    dict(
        name='win_occupiesbg',
        method='Window -[occupiesBackgroundContents]',
        types='c8@0:4',
        start=13211536,
        end=13211564,
        disasm='disasm_worldtileloader_win_occupiesbg.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00c997ac (listing bound); next ObjC IMP 0x00c99a14 MJColorWell -[initWithFrame:cache:windowInfo:color:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13211536, 'sub sp, sp, 8'), (13211560, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Window occupiesBackgroundContents] (imp 0x00c99790, 7w): returns **1** (`movw r2, 1; sxtb r0, r2`) - the window occupies background contents (the tile-pass tie of the window sprite).\n'),
    ),
    dict(
        name='st3_setwbchoice',
        method='SteamTrain -[setWorkbenchChoiceUIOption:]',
        types='v12@0:4i8',
        start=13826276,
        end=13826776,
        disasm='disasm_worldtileloader_st3_setwbchoice.txt',
        base_add=13826288,
        base_literal=13826772,
        boundary='ARM.exidx end 0x00d2fad8 (listing bound); next ObjC IMP 0x00d2fad8 SteamTrain -[actionTitle]',
        selectors={},
        imports={},
        ivars={
                 0xd2fab4: (17168344, 'OBJC_IVAR_$_SteamTrain.leftStationName', 272),
                 0xd2fab8: (17168324, 'OBJC_IVAR_$_SteamTrain.stopAtGoalPos', 324),
                 0xd2fabc: (17168320, 'OBJC_IVAR_$_SteamTrain.stopped', 325),
                 0xd2fac0: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
                 0xd2fac4: (17168332, 'OBJC_IVAR_$_SteamTrain.leftStationGoalPos', 300),
                 0xd2fac8: (17168336, 'OBJC_IVAR_$_SteamTrain.stationGoalPos', 316),
                 0xd2facc: (17168348, 'OBJC_IVAR_$_SteamTrain.rightStationName', 276),
                 0xd2fad0: (17168328, 'OBJC_IVAR_$_SteamTrain.rightStationGoalPos', 308),
        },
        classes={},
        instructions=[(13826276, 'push {r4, r5, r6, r7, fp, lr}'), (13826364, 'and r0, r0, 1'), (13826380, 'strb r0, [r1]'), (13826500, 'movw r3, 1'), (13826772, 'ldrshteq r0, [r3], -ip')],
        calls=[],
        branches=[(13826440, 'beq', 13826568), (13826476, 'bne', 13826568), (13826604, 'beq', 13826732), (13826640, 'beq', 13826732)],
        semantics=('[SteamTrain setWorkbenchChoiceUIOption:] (imp 0x00d2f8e4, 125w): the four-cell chain - fffffce4/fcd0/fccc/fcc8 ivar cells; the flag is **inverted-booleanized** (`cmp r0, 0; movw r0, 0; movne r0, 1; eor r0, r0, 1; and r0, r0, 1` @0xc2f92c-0xc2f93c) then `strb` (@0xd2f94c) + two zero `strb` (@0xd2f95c/@0xd2f96c); the fffffcd8/fcdc cells + `movw r3, 1` follow with the choice-UI refresh gate.\n'),
    ),
    dict(
        name='st3_fuelcount',
        method='SteamTrain -[fuelCount]',
        types='i8@0:4',
        start=13827288,
        end=13827496,
        disasm='disasm_worldtileloader_st3_fuelcount.txt',
        base_add=13827296,
        base_literal=13827492,
        boundary='ARM.exidx end 0x00d2fda8 (listing bound); next ObjC IMP 0x00d2fda8 SteamTrain -[fuelItemCount]',
        selectors={},
        imports={},
        ivars={
                 0xd2fda0: (17168312, 'OBJC_IVAR_$_SteamTrain.fuelFraction', 260),
        },
        classes={},
        instructions=[(13827288, 'sub sp, sp, 0x28'), (13827352, 'vcvt.s32.f32 s0, s0'), (13827376, 'cmp r0, r1'), (13827436, 'cmp r0, r1'), (13827492, 'eorseq pc, r2, ip, lsl 28')],
        calls=[],
        branches=[(13827380, 'bge', 13827396), (13827392, 'b', 13827404), (13827440, 'bge', 13827456), (13827452, 'b', 13827464)],
        semantics=('[SteamTrain fuelCount] (imp 0x00d2fcd8, 52w): the float math - `movw r3, 0xa` (10) + the fffffcc4 cell read + `vmul.f32 s2, s4, s2; vadd.f32 s0, s2, s0; vcvt.s32.f32` (@0xd2fd10-0xd2fd18: the fractional fuel accumulator to int) + the two clamp compares (`cmp r0, r1; bge` @0xd2fd30 and `cmp r0, r1; bge` @0xd2fd6c with `movw r1, 0` floors) - the fuel count integer with its [0, 10] bounds.\n'),
    ),
    dict(
        name='st3_fuelitemcount',
        method='SteamTrain -[fuelItemCount]',
        types='i8@0:4',
        start=13827496,
        end=13827572,
        disasm='disasm_worldtileloader_st3_fuelitemcount.txt',
        base_add=13827532,
        base_literal=13827568,
        boundary='ARM.exidx end 0x00d2fdf4 (listing bound); next ObjC IMP 0x00d2fdc4 SteamTrain -[fuelItems]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13827496, 'sub sp, sp, 8'), (13827568, 'eorseq pc, r2, r0, lsr 26')],
        calls=[],
        branches=[],
        semantics=('[SteamTrain fuelItemCount] (imp 0x00d2fda8, 19w): returns **4** (`movw r2, 4`) - the fuel item count constant of the train.\n'),
    ),
    dict(
        name='st3_fuelitems',
        method='SteamTrain -[fuelItems]',
        types='^i8@0:4',
        start=13827524,
        end=13827572,
        disasm='disasm_worldtileloader_st3_fuelitems.txt',
        base_add=13827532,
        base_literal=13827568,
        boundary='ARM.exidx end 0x00d2fdf4 (listing bound); next ObjC IMP 0x00d2fdf4 SteamTrain -[updateHasFuel]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13827524, 'sub sp, sp, 8'), (13827552, 'mov r0, r2'), (13827568, 'eorseq pc, r2, r0, lsr 26')],
        calls=[],
        branches=[],
        semantics=('[SteamTrain fuelItems] (imp 0x00d2fdc4, 12w): returns the address of a **global table** (the e171a8 PIC cell resolves below the scanned window @0xb46f80 = the shared data-section thunk target) - the fuel-items list pointer.\n'),
    ),
    dict(
        name='st3_fueluipos',
        method='SteamTrain -[fuelUIPos]',
        types='{Vector2=[2f]}8@0:4',
        start=13829380,
        end=13829504,
        disasm='disasm_worldtileloader_st3_fueluipos.txt',
        base_add=13829412,
        base_literal=13829500,
        boundary='ARM.exidx end 0x00d30580 (listing bound); next ObjC IMP 0x00d30580 SteamTrain -[setNeedsRemoved:]',
        selectors={},
        imports={},
        ivars={
                 0xd30578: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(13829380, 'push {fp, lr}'), (13829440, 'movt ip, 0x4080'), (13829484, 'bl method.Vector2.operator_Vector2_'), (13829500, 'eorseq pc, r2, r8, asr 11')],
        calls=[(13829464, 'bl method.Vector2.Vector2_float__float_'), (13829484, 'bl method.Vector2.operator_Vector2_')],
        branches=[],
        semantics=("[SteamTrain fuelUIPos] (imp 0x00d30504, 31w): returns `Vector2::operator+(Vector2::Vector2(0, 4.0f))` (@0xd30540: `movw ip, 0; movt ip, 0x4080` = **0x40800000 = 4.0f**) over the train's macro position (ffffc8dc chain) - the fuel UI anchor floats 4 units above the train.\n"),
    ),
    dict(
        name='st3_needschoice',
        method='SteamTrain -[needsToUpdateChoiceUI]',
        types='c8@0:4',
        start=13832952,
        end=13833012,
        disasm='disasm_worldtileloader_st3_needschoice.txt',
        base_add=13832960,
        base_literal=13833008,
        boundary='ARM.exidx end 0x00d31334 (listing bound); next ObjC IMP 0x00d31334 SteamTrain -[setNeedsToUpdateChoiceUI:]',
        selectors={},
        imports={},
        ivars={
                 0xd3132c: (17168364, 'OBJC_IVAR_$_SteamTrain.needsToUpdateChoiceUI', 326),
        },
        classes={},
        instructions=[(13832952, 'sub sp, sp, 8'), (13832992, 'ldrsb r0, [r0]'), (13833008, 'eorseq lr, r2, ip, ror 15')],
        calls=[],
        branches=[],
        semantics=('[SteamTrain needsToUpdateChoiceUI] (imp 0x00d312f8, 15w): `ldrsb` of the fffffcf8 cell byte - the choice-UI dirty flag read.\n'),
    ),
    dict(
        name='st3_setneedschoice',
        method='SteamTrain -[setNeedsToUpdateChoiceUI:]',
        types='v12@0:4c8',
        start=13833012,
        end=13833080,
        disasm='disasm_worldtileloader_st3_setneedschoice.txt',
        base_add=13833040,
        base_literal=13833076,
        boundary='ARM.exidx end 0x00d31378 (listing bound); next ObjC IMP 0x00d31378 SteamTrain -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0xd31370: (17168364, 'OBJC_IVAR_$_SteamTrain.needsToUpdateChoiceUI', 326),
        },
        classes={},
        instructions=[(13833012, 'sub sp, sp, 0xc'), (13833052, 'dmb ish'), (13833056, 'strb r2, [r0, r1]'), (13833076, 'mlaseq r2, ip, r7, lr')],
        calls=[],
        branches=[],
        semantics=("[SteamTrain setNeedsToUpdateChoiceUI:] (imp 0x00d31334, 17w): the **dmb ish**-fenced store - `strb r2, [sp, 3]` then the fffffcf8 cell + **dmb ish; strb r2, [r0, r1]; dmb ish** (@0xd3135c-0xd31368): the choice-UI flag is written with explicit SMP barriers (the game's atomic-flag idiom).\n"),
    ),
    dict(
        name='st3_candismiss',
        method='SteamTrain -[canDismissFuelUI]',
        types='c8@0:4',
        start=13829324,
        end=13829380,
        disasm='disasm_worldtileloader_st3_candismiss.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d30504 (listing bound); next ObjC IMP 0x00d304e8 SteamTrain -[requiresFuel]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13829324, 'sub sp, sp, 8'), (13829376, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[SteamTrain canDismissFuelUI] (imp 0x00d304cc, 14w): returns **0** (movw r2, 0; sxtb) - the fuel UI cannot be dismissed.\n'),
    ),
    dict(
        name='st3_requiresfuel',
        method='SteamTrain -[requiresFuel]',
        types='c8@0:4',
        start=13829352,
        end=13829380,
        disasm='disasm_worldtileloader_st3_requiresfuel.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d30504 (listing bound); next ObjC IMP 0x00d30504 SteamTrain -[fuelUIPos]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13829352, 'sub sp, sp, 8'), (13829376, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[SteamTrain requiresFuel] (imp 0x00d304e8, 7w): returns **1**.\n'),
    ),
    dict(
        name='st3_isengine',
        method='SteamTrain -[isEngine]',
        types='c8@0:4',
        start=13832300,
        end=13832328,
        disasm='disasm_worldtileloader_st3_isengine.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d31088 (listing bound); next ObjC IMP 0x00d31088 SteamTrain -[removeRider:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13832300, 'sub sp, sp, 8'), (13832324, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[SteamTrain isEngine] (imp 0x00d3106c, 7w): returns **1** - the SteamTrain is an engine-class rail vehicle.\n'),
    ),
    dict(
        name='st3_maxriders',
        method='SteamTrain -[maxNumberOfRiders]',
        types='i8@0:4',
        start=13832668,
        end=13832696,
        disasm='disasm_worldtileloader_st3_maxriders.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d311f8 (listing bound); next ObjC IMP 0x00d311f8 SteamTrain -[railOrStationNameChanged]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13832668, 'sub sp, sp, 8'), (13832692, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[SteamTrain maxNumberOfRiders] (imp 0x00d311dc, 7w): returns **1** - single rider.\n'),
    ),
    dict(
        name='st3_settargetvel',
        method='SteamTrain -[setTargetVelocity:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=13826220,
        end=13826248,
        disasm='disasm_worldtileloader_st3_settargetvel.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d2f8c8 (listing bound); next ObjC IMP 0x00d2f8c8 SteamTrain -[itemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13826220, 'sub sp, sp, 0x10'), (13826244, 'bx lr')],
        calls=[],
        branches=[],
        semantics=("[SteamTrain setTargetVelocity:] (imp 0x00d2f8ac, 7w): **empty body** - the target-velocity setter is a no-op (the train's motion is computed, not externally set).\n"),
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
        'batch': 'Window + SteamTrain smalls cluster (E71): the window ctor/record/dealloc family, draw marshalling, occupiesBackgroundContents, and the steamtrain fuel/choice accessors incl. the dmb-fenced flag; 22 bodies',
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
                        default=NATIVE / 'window_smalls.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale window_smalls.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
