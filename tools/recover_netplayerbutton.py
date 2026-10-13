#!/usr/bin/env python3
"""Hash-gated recovery of the NetPlayerButton (E156).

The multiplayer player-row button lands: the batch sweeps the button surface:
36 bodies, {total} instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/NETPLAYERBUTTON.md for the prose and boundaries.
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
    'bl 0x7853a8': 0x007853a8,
    'bl 0x787bc8': 0x00787bc8,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
}

SPECS = [
    dict(
        name='npb_00',
        method='NetPlayerButton -[banButtonTapped]',
        types='v8@0:4',
        start=7899032,
        end=7899160,
        disasm='disasm_worldtileloader_npb_00.txt',
        base_add=7899048,
        base_literal=7899156,
        boundary='ARM.exidx end 0x00788818 (listing bound); next ObjC IMP 0x00788818 NetPlayerButton -[kickButtonTapped]',
        selectors={
                 0x788808: (15209084, 'banPlayerWithNameFromPlayerButton:'),
        },
        imports={
                 0x788804: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x78880c: (17159972, 'OBJC_IVAR_$_NetPlayerButton.playerName', 312),
                 0x788810: (17159948, 'OBJC_IVAR_$_NetPlayerButton.world', 280),
        },
        classes={},
        instructions=[(7899032, 'push {r4, sl, fp, lr}'), (7899156, 'addeq r7, sp, r4, asr 6')],
        calls=[(7899128, 'blx r3')],
        branches=[],
        semantics=('NetPlayerButton -[banButtonTapped] @0x00788798 (32 words, 0 branches, 1 call): [self->world banPlayerWithNameFromPlayerButton:self->playerName] - loads the world@280 and playerName@312 offset cells (0x00788810/0x0078880c) off the PIC base (0x00788814 -> 0x8d7344 + pc) and issues one objc_msgSend through the import cell 0x00788804 (cell 0xffffbcac) via \'blx r3\'; self/_cmd only spilled, no branch, no result use.'),
    ),
    dict(
        name='npb_01',
        method='NetPlayerButton -[buttonAction:]',
        types='v12@0:4@8',
        start=7897480,
        end=7898296,
        disasm='disasm_worldtileloader_npb_01.txt',
        base_add=7897496,
        base_literal=7898292,
        boundary='ARM.exidx end 0x007884b8 (listing bound); next ObjC IMP 0x007884b8 NetPlayerButton -[textToggleButtonTapped]',
        selectors={
                 0x788480: (15209052, 'canZoomCameraToOtherPlayer'),
                 0x788488: (15209056, 'zoomButtonTappedForButton:'),
                 0x788490: (15209068, 'hideChatView'),
                 0x788498: (15209064, 'initWithWindowInfo:netPlayerButton:cache:localPlayerIsMod:showReportButton:'),
                 0x78849c: (15209060, 'isCloudGame'),
                 0x7884a0: (15209004, 'isMod'),
                 0x7884ac: (15208936, 'alloc'),
        },
        imports={
                 0x78847c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x788478: (17160008, 'OBJC_IVAR_$_NetPlayerButton.local', 305),
                 0x788484: (17159952, 'OBJC_IVAR_$_NetPlayerButton.worldUI', 284),
                 0x78848c: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
                 0x788494: (17159948, 'OBJC_IVAR_$_NetPlayerButton.world', 280),
                 0x7884a4: (17155620, 'OBJC_IVAR_$_MJView.cache', 48),
                 0x7884a8: (17155636, 'OBJC_IVAR_$_MJView.windowInfo', 52),
        },
        classes={
                 0x7884b0: (15246992, 'OBJC_CLASS_$_NetPlayerUI'),
        },
        instructions=[(7897480, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7898292, 'addeq r7, sp, r4, asr sb')],
        calls=[(7897608, 'blx r2'), (7897692, 'blx r3'), (7897944, 'blx r2'), (7898048, 'blx lr'), (7898096, 'blx ip'), (7898164, 'blx r5'), (7898220, 'blx ip')],
        branches=[(7897544, 'bne', 7897700), (7897620, 'beq', 7897696), (7897696, 'b', 7897700), (7897736, 'bne', 7898224)],
        semantics=('NetPlayerButton -[buttonAction:] @0x00788188 (204 words, 4 branches, 7 calls): menu-open handler, ignores its argument (spilled at fp-0x24, never read; re-sends pass self). If !self->local@305 and [self->worldUI@284 canZoomCameraToOtherPlayer] (0x00788208) then [self->worldUI zoomButtonTappedForButton:self] (0x0078825c). Then, only when self->playerUI@292 is nil, it builds the row popup: [[NetPlayerUI alloc] initWithWindowInfo:self->windowInfo netPlayerButton:self cache:self->cache localPlayerIsMod:[self->world isMod] showReportButton:[self->world isCloudGame]] (0x00788430; isMod/isCloudGame BOOLs sign-extended onto the stack) and stores it to playerUI@292, then [self->world hideChatView] (0x0078846c). All calls via blx r2/r3/lr/ip/r5.'),
    ),
    dict(
        name='npb_02',
        method='NetPlayerButton -[cloudMode]',
        types='i8@0:4',
        start=7900404,
        end=7900464,
        disasm='disasm_worldtileloader_npb_02.txt',
        base_add=7900428,
        base_literal=7900460,
        boundary='ARM.exidx end 0x00788d30 (listing bound); next ObjC IMP 0x00788d30 NetPlayerButton -[setCloudMode:]',
        selectors={},
        imports={},
        ivars={
                 0x788d28: (17159956, 'OBJC_IVAR_$_NetPlayerButton.cloudMode', 324),
        },
        classes={},
        instructions=[(7900404, 'sub sp, sp, 8'), (7900460, 'addeq r6, sp, r0, ror 27')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[cloudMode] @0x00788cf4 (15 words, 0 calls): Apportable offset-cell getter - PIC base from cell 0x00788d2c (0x8d6de0 + pc), ivar cell 0x00788d28 (0xffffdc20) resolves OBJC_IVAR_$_NetPlayerButton.cloudMode, returns the int at self+cloudMode@324 with a \'dmb ish\' before bx lr.'),
    ),
    dict(
        name='npb_03',
        method='NetPlayerButton -[connected]',
        types='c8@0:4',
        start=7899892,
        end=7899952,
        disasm='disasm_worldtileloader_npb_03.txt',
        base_add=7899900,
        base_literal=7899948,
        boundary='ARM.exidx end 0x00788b30 (listing bound); next ObjC IMP 0x00788b30 NetPlayerButton -[setConnected:]',
        selectors={},
        imports={},
        ivars={
                 0x788b28: (17159964, 'OBJC_IVAR_$_NetPlayerButton.connected', 317),
        },
        classes={},
        instructions=[(7899892, 'sub sp, sp, 8'), (7899948, 'strdeq r6, r7, [sp], r0')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[connected] @0x00788af4 (15 words, 0 calls): offset-cell getter for the char connected@317 (cell 0x00788b28, PIC base 0x00788b2c); ldrsb sign-extends the byte result.'),
    ),
    dict(
        name='npb_04',
        method='NetPlayerButton -[dealloc]',
        types='v8@0:4',
        start=7885812,
        end=7886232,
        disasm='disasm_worldtileloader_npb_04.txt',
        base_add=7885828,
        base_literal=7886228,
        boundary='ARM.exidx end 0x00785598 (listing bound); next ObjC IMP 0x00785598 NetPlayerButton -[setFrame:windowInfo:alignment:]',
        selectors={
                 0x785570: (15208956, 'dealloc'),
                 0x78557c: (15208952, 'release'),
        },
        imports={
                 0x78556c: (17151900, 'objc_msgSendSuper2'),
                 0x785578: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x785580: (17159972, 'OBJC_IVAR_$_NetPlayerButton.playerName', 312),
                 0x785584: (17159976, 'OBJC_IVAR_$_NetPlayerButton.mutedImage', 300),
                 0x785588: (17159940, 'OBJC_IVAR_$_NetPlayerButton.avatarImage', 296),
                 0x78558c: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
                 0x785590: (17159984, 'OBJC_IVAR_$_NetPlayerButton.playerID', 308),
        },
        classes={
                 0x785574: (15252784, 'OBJC_CLASS_$_NetPlayerButton'),
        },
        instructions=[(7885812, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7886228, 'addeq sl, sp, r8, ror 13')],
        calls=[(7885992, 'blx r5'), (7886028, 'blx r3'), (7886064, 'blx r3'), (7886100, 'blx r3'), (7886136, 'blx r3'), (7886176, 'blx r2')],
        branches=[],
        semantics=('NetPlayerButton -[dealloc] @0x007853f4 (105 words, 0 branches, 6 calls): releases exactly five object ivars in order playerID@308, playerUI@292, avatarImage@296, mutedImage@300, playerName@312 (each via the two-stage offset cell + objc_msgSend release), then objc_msgSendSuper2({self, NetPlayerButton class cell 0x00785574}, @selector(dealloc)) at 0x00785560. standardShader@276, world@280 and worldUI@284 are NOT released (observed asymmetry with the ctor/setter paths). No branches; frame fp = sp+0x18, sub sp,#0x40.'),
    ),
    dict(
        name='npb_05',
        method='NetPlayerButton -[endTouch:]',
        types='v16@0:4{CGPoint=ff}8',
        start=7897008,
        end=7897480,
        disasm='disasm_worldtileloader_npb_05.txt',
        base_add=7897024,
        base_literal=7897476,
        boundary='ARM.exidx end 0x00788188 (listing bound); next ObjC IMP 0x00788188 NetPlayerButton -[buttonAction:]',
        selectors={
                 0x788168: (15209036, 'touchIsInUI:'),
                 0x788174: (15209048, 'endTouch:'),
                 0x78817c: (15208980, 'autorelease'),
        },
        imports={
                 0x788178: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x788160: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
        },
        classes={
                 0x78816c: (15252784, 'OBJC_CLASS_$_NetPlayerButton'),
        },
        instructions=[(7897008, 'push {r4, r5, fp, lr}'), (7897476, 'addeq r7, sp, ip, lsr 22')],
        calls=[(7897152, 'bl loc.imp.objc_msgSend'), (7897252, 'bl loc.imp.objc_msgSendSuper2'), (7897336, 'blx r3'), (7897428, 'bl loc.imp.objc_msgSend')],
        branches=[(7897088, 'beq', 7897176), (7897164, 'bne', 7897176), (7897264, 'beq', 7897368)],
        semantics=('NetPlayerButton -[endTouch:] @0x00787fb0 (118 words, 3 branches, 4 calls): point in r2/r3. clear=NO (fp-0x19=0); if self->playerUI@292 != nil and ![self->playerUI touchIsInUI:point] (0x00788040) then clear=YES. Always [super endTouch:point] via objc_msgSendSuper2 with class cell 0x0078816c; if clear then playerUI is dropped: objc_msgSend(playerUI, @selector(autorelease)) (0x007880f8) followed by the inline strong store of 0 into the playerUI slot (Apportable objc_storeStrong nil form). Tail re-reads playerUI and sends [self->playerUI endTouch:point] via objc_msgSend (0x00788154).'),
    ),
    dict(
        name='npb_06',
        method='NetPlayerButton -[initWithFrame:cache:windowInfo:alignment:world:worldUI:]',
        types='@44@0:4{CGRect={CGPoint=ff}{CGSize=ff}}8@24^{WindowInfo=ffffffff}28i32@36@40',
        start=7884316,
        end=7885736,
        disasm='disasm_worldtileloader_npb_06.txt',
        base_add=7884332,
        base_literal=7885732,
        boundary='ARM.exidx end 0x007853a8 (listing bound); next ObjC IMP 0x007853f4 NetPlayerButton -[dealloc]',
        selectors={
                 0x785318: (15208908, 'initWithFrame:cache:windowInfo:textureName:'),
                 0x785320: (15208948, 'setTarget:action:'),
                 0x785324: (15208944, 'buttonAction:'),
                 0x785344: (15208912, 'standardUserDefaults'),
                 0x785348: (15208916, 'boolForKey:'),
                 0x78535c: (15208920, 'textureNamed:'),
                 0x785364: (15208924, 'setBackgroundSelectedTexture:'),
                 0x78536c: (15208928, 'arrayWithObjects:'),
                 0x785380: (15208932, 'shaderNamed:attributes:uniforms:'),
                 0x785398: (15208936, 'alloc'),
                 0x7853a0: (15208940, 'initWithFrame:cache:windowInfo:texture:'),
        },
        imports={
                 0x785308: (16318728, '__CFConstantStringClassReference'),
                 0x78531c: (17151904, 'objc_msgSend'),
                 0x78534c: (16318744, '__CFConstantStringClassReference'),
                 0x785360: (16318760, '__CFConstantStringClassReference'),
                 0x785370: (16318792, '__CFConstantStringClassReference'),
                 0x785374: (16318808, '__CFConstantStringClassReference'),
                 0x785378: (16318824, '__CFConstantStringClassReference'),
                 0x78537c: (16318840, '__CFConstantStringClassReference'),
                 0x785384: (16318776, '__CFConstantStringClassReference'),
                 0x78538c: (16318856, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x785328: (17159940, 'OBJC_IVAR_$_NetPlayerButton.avatarImage', 296),
                 0x78532c: (17159944, 'OBJC_IVAR_$_NetPlayerButton.alignment', 288),
                 0x785334: (17159948, 'OBJC_IVAR_$_NetPlayerButton.world', 280),
                 0x785338: (17159952, 'OBJC_IVAR_$_NetPlayerButton.worldUI', 284),
                 0x78533c: (17159956, 'OBJC_IVAR_$_NetPlayerButton.cloudMode', 324),
                 0x785350: (17159960, 'OBJC_IVAR_$_NetPlayerButton.textChatEnabled', 316),
                 0x785354: (17159964, 'OBJC_IVAR_$_NetPlayerButton.connected', 317),
                 0x785358: (17155620, 'OBJC_IVAR_$_MJView.cache', 48),
                 0x785388: (17159968, 'OBJC_IVAR_$_NetPlayerButton.standardShader', 276),
                 0x785390: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0x78539c: (17155636, 'OBJC_IVAR_$_MJView.windowInfo', 52),
        },
        classes={
                 0x785310: (15252784, 'OBJC_CLASS_$_NetPlayerButton'),
                 0x785340: (15246972, 'OBJC_CLASS_$_NSUserDefaults'),
                 0x785368: (15246976, 'OBJC_CLASS_$_NSArray'),
                 0x785394: (15246980, 'OBJC_CLASS_$_MJImageView'),
        },
        instructions=[(7884316, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7885732, 'addeq sl, sp, r0, asr 25')],
        calls=[(7884572, 'bl loc.imp.objc_msgSendSuper2'), (7884800, 'bl loc.imp.objc_msgSend'), (7884824, 'bl loc.imp.objc_msgSend'), (7884948, 'bl loc.imp.objc_msgSend'), (7884980, 'bl loc.imp.objc_msgSend'), (7885068, 'bl loc.imp.objc_msgSend'), (7885136, 'bl loc.imp.objc_msgSend'), (7885176, 'bl loc.imp.objc_msgSend'), (7885236, 'bl loc.imp.objc_msgSend'), (7885332, 'bl 0x7853a8'), (7885356, 'bl loc.imp.objc_msgSend'), (7885488, 'bl loc.imp.objc_msgSend'), (7885552, 'blx lr')],
        branches=[(7884600, 'bne', 7884616), (7884612, 'b', 7885564)],
        semantics=('NetPlayerButton -[initWithFrame:cache:windowInfo:alignment:world:worldUI:] @0x00784e1c (355 words, 2 branches, 13 calls): designated initializer. Super via objc_msgSendSuper2({self,NetPlayerButton}, @selector(initWithFrame:cache:windowInfo:textureName:)) with textureName = CFString 0xf90108 \'InventoryButtonBackground.png\' (0x00784f1c); nil guard returns nil. Then stores alignment@288, world@280, worldUI@284 from the stack args, cloudMode@324 = 0, connected@317 = 1, and textChatEnabled@316 = ![[NSUserDefaults standardUserDefaults] boolForKey:@"textChatDisabled"] (CFString 0xf90118). Caches the pressed texture [self->cache textureNamed:@"InventoryButtonBackgroundSelected.png"] (0xf90128) -> setBackgroundSelectedTexture:. Builds standardShader@276 = [self shaderNamed:@"StandardObject" (0xf90138) attributes:[NSArray arrayWithObjects:@"position" (0xf90148), @"texCoord" (0xf90158), nil] uniforms:[NSArray arrayWithObjects:@"mvp_matrix" (0xf90168), @"texture" (0xf90178), nil]]. Creates avatarImage@296 = [[MJImageView alloc] initWithFrame:{x+4,y+4,w-8,h-8} cache:self->cache windowInfo:self->windowInfo texture:[self->cache textureNamed:@"noGCAvatar.png"]] - the inset rect is packed by the 4-float helper at 0x007853a8 (bl 0x7853a8) using vmov.f32 #16 (4.0) / #32 (8.0). Ends with [self setTarget:self action:@selector(buttonAction:)] (0x007852f0) and returns self; frame sub sp,#0xd8.'),
    ),
    dict(
        name='npb_07',
        method='NetPlayerButton -[isAdmin]',
        types='c8@0:4',
        start=7900148,
        end=7900208,
        disasm='disasm_worldtileloader_npb_07.txt',
        base_add=7900156,
        base_literal=7900204,
        boundary='ARM.exidx end 0x00788c30 (listing bound); next ObjC IMP 0x00788c30 NetPlayerButton -[setIsAdmin:]',
        selectors={},
        imports={},
        ivars={
                 0x788c28: (17159996, 'OBJC_IVAR_$_NetPlayerButton.isAdmin', 319),
        },
        classes={},
        instructions=[(7900148, 'sub sp, sp, 8'), (7900204, 'strdeq r6, r7, [sp], r0')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[isAdmin] @0x00788bf4 (15 words, 0 calls): offset-cell getter, char isAdmin@319 (cell 0x00788c28, base 0x00788c2c), ldrsb.'),
    ),
    dict(
        name='npb_08',
        method='NetPlayerButton -[isMod]',
        types='c8@0:4',
        start=7900276,
        end=7900336,
        disasm='disasm_worldtileloader_npb_08.txt',
        base_add=7900284,
        base_literal=7900332,
        boundary='ARM.exidx end 0x00788cb0 (listing bound); next ObjC IMP 0x00788cb0 NetPlayerButton -[setIsMod:]',
        selectors={},
        imports={},
        ivars={
                 0x788ca8: (17160000, 'OBJC_IVAR_$_NetPlayerButton.isMod', 320),
        },
        classes={},
        instructions=[(7900276, 'sub sp, sp, 8'), (7900332, 'addeq r6, sp, r0, ror lr')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[isMod] @0x00788c74 (15 words, 0 calls): offset-cell getter, char isMod@320 (cell 0x00788ca8, base 0x00788cac), ldrsb.'),
    ),
    dict(
        name='npb_09',
        method='NetPlayerButton -[isOwner]',
        types='c8@0:4',
        start=7900020,
        end=7900080,
        disasm='disasm_worldtileloader_npb_09.txt',
        base_add=7900028,
        base_literal=7900076,
        boundary='ARM.exidx end 0x00788bb0 (listing bound); next ObjC IMP 0x00788bb0 NetPlayerButton -[setIsOwner:]',
        selectors={},
        imports={},
        ivars={
                 0x788ba8: (17159992, 'OBJC_IVAR_$_NetPlayerButton.isOwner', 318),
        },
        classes={},
        instructions=[(7900020, 'sub sp, sp, 8'), (7900076, 'addeq r6, sp, r0, ror pc')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[isOwner] @0x00788b74 (15 words, 0 calls): offset-cell getter, char isOwner@318 (cell 0x00788ba8, base 0x00788bac), ldrsb.'),
    ),
    dict(
        name='npb_10',
        method='NetPlayerButton -[kickButtonTapped]',
        types='v8@0:4',
        start=7899160,
        end=7899288,
        disasm='disasm_worldtileloader_npb_10.txt',
        base_add=7899176,
        base_literal=7899284,
        boundary='ARM.exidx end 0x00788898 (listing bound); next ObjC IMP 0x00788898 NetPlayerButton -[reportButtonTapped]',
        selectors={
                 0x788888: (15209088, 'kickPlayerWithNameFromPlayerButton:'),
        },
        imports={
                 0x788884: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x78888c: (17159972, 'OBJC_IVAR_$_NetPlayerButton.playerName', 312),
                 0x788890: (17159948, 'OBJC_IVAR_$_NetPlayerButton.world', 280),
        },
        classes={},
        instructions=[(7899160, 'push {r4, sl, fp, lr}'), (7899284, 'addeq r7, sp, r4, asr 5')],
        calls=[(7899256, 'blx r3')],
        branches=[],
        semantics=('NetPlayerButton -[kickButtonTapped] @0x00788818 (32 words, 0 branches, 1 call): [self->world kickPlayerWithNameFromPlayerButton:self->playerName] - same shape as banButtonTapped, selector cell 0x00788888, ivar cells playerName@312/0x0078888c and world@280/0x00788890, single \'blx r3\' objc_msgSend.'),
    ),
    dict(
        name='npb_11',
        method='NetPlayerButton -[local]',
        types='c8@0:4',
        start=7899636,
        end=7899696,
        disasm='disasm_worldtileloader_npb_11.txt',
        base_add=7899644,
        base_literal=7899692,
        boundary='ARM.exidx end 0x00788a30 (listing bound); next ObjC IMP 0x00788a30 NetPlayerButton -[setLocal:]',
        selectors={},
        imports={},
        ivars={
                 0x788a28: (17160008, 'OBJC_IVAR_$_NetPlayerButton.local', 305),
        },
        classes={},
        instructions=[(7899636, 'sub sp, sp, 8'), (7899692, 'strdeq r7, r8, [sp], r0')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[local] @0x007889f4 (15 words, 0 calls): offset-cell getter, char local@305 (cell 0x00788a28, base 0x00788a2c), ldrsb.'),
    ),
    dict(
        name='npb_12',
        method='NetPlayerButton -[moveTouch:]',
        types='v16@0:4{CGPoint=ff}8',
        start=7896564,
        end=7897008,
        disasm='disasm_worldtileloader_npb_12.txt',
        base_add=7896580,
        base_literal=7897004,
        boundary='ARM.exidx end 0x00787fb0 (listing bound); next ObjC IMP 0x00787fb0 NetPlayerButton -[endTouch:]',
        selectors={
                 0x787f90: (15209036, 'touchIsInUI:'),
                 0x787f98: (15208980, 'autorelease'),
                 0x787fa4: (15209044, 'moveTouch:'),
        },
        imports={
                 0x787f94: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x787f88: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
        },
        classes={
                 0x787f9c: (15252784, 'OBJC_CLASS_$_NetPlayerButton'),
        },
        instructions=[(7896564, 'push {r4, sl, fp, lr}'), (7897004, 'addeq r7, sp, r8, ror 25')],
        calls=[(7896700, 'bl loc.imp.objc_msgSend'), (7896784, 'blx r3'), (7896892, 'bl loc.imp.objc_msgSendSuper2'), (7896956, 'bl loc.imp.objc_msgSend')],
        branches=[(7896636, 'beq', 7896816), (7896712, 'bne', 7896816)],
        semantics=('NetPlayerButton -[moveTouch:] @0x00787df4 (111 words, 2 branches, 4 calls): point in r2/r3. If self->playerUI@292 != nil and ![self->playerUI touchIsInUI:point] (0x00787e7c) the row UI is dismissed: objc_msgSend(playerUI, @selector(autorelease)) (0x00787ed0) then the inline strong store of 0 into the playerUI slot. Then always [super moveTouch:point] (objc_msgSendSuper2, class cell 0x00787f9c) and finally [self->playerUI moveTouch:point] via objc_msgSend (0x00787f7c); the nil early-exit leaves playerUI alone.'),
    ),
    dict(
        name='npb_13',
        method='NetPlayerButton -[muteButtonTapped]',
        types='v8@0:4',
        start=7898672,
        end=7899032,
        disasm='disasm_worldtileloader_npb_13.txt',
        base_add=7898688,
        base_literal=7899028,
        boundary='ARM.exidx end 0x00788798 (listing bound); next ObjC IMP 0x00788798 NetPlayerButton -[banButtonTapped]',
        selectors={
                 0x788778: (15208964, 'windowInfoChanged:'),
                 0x788784: (15209080, 'setPlayerMuted:withID:'),
        },
        imports={
                 0x788774: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x78877c: (17155636, 'OBJC_IVAR_$_MJView.windowInfo', 52),
                 0x788780: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
                 0x788788: (17159984, 'OBJC_IVAR_$_NetPlayerButton.playerID', 308),
                 0x78878c: (17159988, 'OBJC_IVAR_$_NetPlayerButton.muted', 321),
                 0x788790: (17159948, 'OBJC_IVAR_$_NetPlayerButton.world', 280),
        },
        classes={},
        instructions=[(7898672, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7899028, 'addeq r7, sp, ip, lsr 9')],
        calls=[(7898928, 'blx r8'), (7898984, 'blx lr')],
        branches=[],
        semantics=('NetPlayerButton -[muteButtonTapped] @0x00788630 (90 words, 0 branches, 2 calls): toggles self->muted@321 = !self->muted (ldrsb/cmp/movne/eor/and, strb back at 0x007886c0), then [self->world setPlayerMuted:self->muted(new) withID:self->playerID] (0x00788730, BOOL sign-extended) and [self->playerUI windowInfoChanged:self->windowInfo] (0x00788768, MJView.windowInfo@52). Selector cells 0x00788784 (setPlayerMuted:withID:), 0x00788778 (windowInfoChanged:); 8 registers spilled to the stack between the two sends.'),
    ),
    dict(
        name='npb_14',
        method='NetPlayerButton -[muted]',
        types='c8@0:4',
        start=7900532,
        end=7900592,
        disasm='disasm_worldtileloader_npb_14.txt',
        base_add=7900540,
        base_literal=7900588,
        boundary='ARM.exidx end 0x00788db0 (listing bound); next ObjC IMP 0x00788db0 NetPlayerButton -[setMuted:]',
        selectors={},
        imports={},
        ivars={
                 0x788da8: (17159988, 'OBJC_IVAR_$_NetPlayerButton.muted', 321),
        },
        classes={},
        instructions=[(7900532, 'sub sp, sp, 8'), (7900588, 'addeq r6, sp, r0, ror sp')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[muted] @0x00788d74 (15 words, 0 calls): offset-cell getter, char muted@321 (cell 0x00788da8, base 0x00788dac), ldrsb.'),
    ),
    dict(
        name='npb_15',
        method='NetPlayerButton -[playerID]',
        types='@8@0:4',
        start=7899500,
        end=7899568,
        disasm='disasm_worldtileloader_npb_15.txt',
        base_add=7899524,
        base_literal=7899564,
        boundary='ARM.exidx end 0x007889f4; body trimmed at the next IMP 0x007889b0 NetPlayerButton -[playerName]',
        selectors={},
        imports={},
        ivars={
                 0x7889a8: (17159984, 'OBJC_IVAR_$_NetPlayerButton.playerID', 308),
        },
        classes={},
        instructions=[(7899500, 'sub sp, sp, 0xc'), (7899564, 'addeq r7, sp, r8, ror 2')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[playerID] @0x0078896c (17 words, 0 calls): object getter for the NSString playerID@308 - offset cell 0x007889a8 + base 0x007889ac, \'dmb ish\' after the load, result also spilled to [sp,8] before return (Apportable retain/return idiom).'),
    ),
    dict(
        name='npb_16',
        method='NetPlayerButton -[playerName]',
        types='@8@0:4',
        start=7899568,
        end=7899636,
        disasm='disasm_worldtileloader_npb_16.txt',
        base_add=7899592,
        base_literal=7899632,
        boundary='ARM.exidx end 0x007889f4 (listing bound); next ObjC IMP 0x007889f4 NetPlayerButton -[local]',
        selectors={},
        imports={},
        ivars={
                 0x7889ec: (17159972, 'OBJC_IVAR_$_NetPlayerButton.playerName', 312),
        },
        classes={},
        instructions=[(7899568, 'sub sp, sp, 0xc'), (7899632, 'addeq r7, sp, r4, lsr 2')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[playerName] @0x007889b0 (17 words, 0 calls): object getter for the NSString playerName@312 (cell 0x007889ec, base 0x007889f0); \'dmb ish\' after the load, result spilled to [sp,8] and reloaded before bx lr.'),
    ),
    dict(
        name='npb_17',
        method='NetPlayerButton -[playerUIIsVisible]',
        types='c8@0:4',
        start=7899416,
        end=7899500,
        disasm='disasm_worldtileloader_npb_17.txt',
        base_add=7899424,
        base_literal=7899496,
        boundary='ARM.exidx end 0x0078896c (listing bound); next ObjC IMP 0x0078896c NetPlayerButton -[playerID]',
        selectors={},
        imports={},
        ivars={
                 0x788964: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
        },
        classes={},
        instructions=[(7899416, 'sub sp, sp, 8'), (7899496, 'addeq r7, sp, ip, asr 3')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[playerUIIsVisible] @0x00788918 (21 words, 0 calls): returns (self->playerUI@292 != nil) - offset cell 0x00788964, cmp against 0, movweq/movne + and r0,r0,1 + sxtb, returned as BOOL.'),
    ),
    dict(
        name='npb_18',
        method='NetPlayerButton -[renderFrame:projectionMatrix:]',
        types='v76@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12',
        start=7886948,
        end=7888940,
        disasm='disasm_worldtileloader_npb_18.txt',
        base_add=7886968,
        base_literal=7888936,
        boundary='ARM.exidx end 0x0078602c (listing bound); next ObjC IMP 0x0078602c NetPlayerButton -[renderUI:projectionMatrix:]',
        selectors={
                 0x785fe8: (15208968, 'renderFrame:projectionMatrix:'),
                 0x786008: (15208920, 'textureNamed:'),
                 0x786018: (15208936, 'alloc'),
                 0x786020: (15208940, 'initWithFrame:cache:windowInfo:texture:'),
        },
        imports={
                 0x78600c: (16318872, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x785fec: (17155680, 'OBJC_IVAR_$_MJView.hidden', 4),
                 0x785ff0: (17159988, 'OBJC_IVAR_$_NetPlayerButton.muted', 321),
                 0x785ff4: (17159940, 'OBJC_IVAR_$_NetPlayerButton.avatarImage', 296),
                 0x785ffc: (17159976, 'OBJC_IVAR_$_NetPlayerButton.mutedImage', 300),
                 0x786000: (17155620, 'OBJC_IVAR_$_MJView.cache', 48),
                 0x786010: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0x78601c: (17155636, 'OBJC_IVAR_$_MJView.windowInfo', 52),
        },
        classes={
                 0x785fe0: (15252784, 'OBJC_CLASS_$_NetPlayerButton'),
                 0x786014: (15246980, 'OBJC_CLASS_$_MJImageView'),
        },
        instructions=[(7886948, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7888936, 'addeq sl, sp, r4, ror r2')],
        calls=[(7887576, 'bl loc.imp.objc_msgSendSuper2'), (7887772, 'bl loc.imp.objc_msgSend'), (7887868, 'bl 0x7853a8'), (7887892, 'bl loc.imp.objc_msgSend'), (7888024, 'bl loc.imp.objc_msgSend'), (7888424, 'bl loc.imp.objc_msgSend'), (7888848, 'bl loc.imp.objc_msgSend')],
        branches=[(7887612, 'beq', 7887620), (7887616, 'b', 7888856), (7887652, 'beq', 7888432), (7887692, 'bne', 7888048), (7888428, 'b', 7888856), (7888468, 'beq', 7888852), (7888852, 'b', 7888856)],
        semantics=('NetPlayerButton -[renderFrame:projectionMatrix:] @0x00785864 (498 words, 7 branches, 7 calls): 4KB+ frame (sub sp,#0x230, bic sp,#0xf); first [super renderFrame:proj] with the 64-byte GLKMatrix4 copied to the stack and re-passed via objc_msgSendSuper2 (class cell 0x00785fe0). If self->hidden (MJView.hidden@4) -> return. If self->muted@321: lazily create mutedImage@300 = [[MJImageView alloc] initWithFrame:CGRectInset(self->frame,4,4) cache:self->cache windowInfo:self->windowInfo texture:[self->cache textureNamed:@"avatarMuted.png"]] (CFString 0xf90198, rect packed by bl 0x7853a8 with vmov #16/#32 = 4.0/8.0) and then [mutedImage renderFrame:pt proj]; else if avatarImage@296 is nil return early, otherwise [avatarImage renderFrame:pt proj]. Both render calls are objc_msgSend with the matrix rebuilt on the stack (0x00785e28 / 0x00785fd0); the r2 \'frame\' argument is preserved in s0 across the whole body.'),
    ),
    dict(
        name='npb_19',
        method='NetPlayerButton -[renderUI:projectionMatrix:]',
        types='v76@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12',
        start=7888940,
        end=7889560,
        disasm='disasm_worldtileloader_npb_19.txt',
        base_add=7889176,
        base_literal=7889552,
        boundary='ARM.exidx end 0x00786298 (listing bound); next ObjC IMP 0x00786298 NetPlayerButton -[setFrame:]',
        selectors={
                 0x786294: (15208968, 'renderFrame:projectionMatrix:'),
        },
        imports={},
        ivars={
                 0x78628c: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
        },
        classes={},
        instructions=[(7888940, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7889556, 'invalid')],
        calls=[(7889536, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('NetPlayerButton -[renderUI:projectionMatrix:] @0x0078602c (155 words, 0 branches, 1 call): pure name-mapping trampoline - copies the 64-byte matrix argument (fp+8..fp+0x44) into a fresh stack frame and issues a single objc_msgSend to [self->playerUI@292 renderFrame:r2 projectionMatrix:matrix] (0x00786280); the first argument (r2, kept in s0) is forwarded unmodified; no nil check (msgSend-to-nil). Frame sub sp,#0x120 + bic sp,#0xf.'),
    ),
    dict(
        name='npb_20',
        method='NetPlayerButton -[reportButtonTapped]',
        types='v8@0:4',
        start=7899288,
        end=7899416,
        disasm='disasm_worldtileloader_npb_20.txt',
        base_add=7899304,
        base_literal=7899412,
        boundary='ARM.exidx end 0x00788918 (listing bound); next ObjC IMP 0x00788918 NetPlayerButton -[playerUIIsVisible]',
        selectors={
                 0x788908: (15209092, 'reportButtonTappedForPlayer:'),
        },
        imports={
                 0x788904: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x78890c: (17159972, 'OBJC_IVAR_$_NetPlayerButton.playerName', 312),
                 0x788910: (17159948, 'OBJC_IVAR_$_NetPlayerButton.world', 280),
        },
        classes={},
        instructions=[(7899288, 'push {r4, sl, fp, lr}'), (7899412, 'addeq r7, sp, r4, asr 4')],
        calls=[(7899384, 'blx r3')],
        branches=[],
        semantics=('NetPlayerButton -[reportButtonTapped] @0x00788898 (32 words, 0 branches, 1 call): [self->world reportButtonTappedForPlayer:self->playerName] - selector cell 0x00788908, ivar cells playerName@312/0x0078890c, world@280/0x00788910, one objc_msgSend via \'blx r3\'.'),
    ),
    dict(
        name='npb_21',
        method='NetPlayerButton -[setCloudMode:]',
        types='v12@0:4i8',
        start=7900464,
        end=7900532,
        disasm='disasm_worldtileloader_npb_21.txt',
        base_add=7900492,
        base_literal=7900528,
        boundary='ARM.exidx end 0x00788d74 (listing bound); next ObjC IMP 0x00788d74 NetPlayerButton -[muted]',
        selectors={},
        imports={},
        ivars={
                 0x788d6c: (17159956, 'OBJC_IVAR_$_NetPlayerButton.cloudMode', 324),
        },
        classes={},
        instructions=[(7900464, 'sub sp, sp, 0xc'), (7900528, 'addeq r6, sp, r0, lsr 27')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[setCloudMode:] @0x00788d30 (17 words, 0 calls): plain int setter - str r2 to self+cloudMode@324 (cell 0x00788d6c, base 0x00788d70) with \'dmb ish\' both before and after the store (inline atomic form).'),
    ),
    dict(
        name='npb_22',
        method='NetPlayerButton -[setConnected:]',
        types='v12@0:4c8',
        start=7899952,
        end=7900020,
        disasm='disasm_worldtileloader_npb_22.txt',
        base_add=7899980,
        base_literal=7900016,
        boundary='ARM.exidx end 0x00788b74 (listing bound); next ObjC IMP 0x00788b74 NetPlayerButton -[isOwner]',
        selectors={},
        imports={},
        ivars={
                 0x788b6c: (17159964, 'OBJC_IVAR_$_NetPlayerButton.connected', 317),
        },
        classes={},
        instructions=[(7899952, 'sub sp, sp, 0xc'), (7900016, 'addeq r6, sp, r0, lsr 31')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[setConnected:] @0x00788b30 (17 words, 0 calls): char setter - arg spilled to [sp,3], strb r2 to self+connected@317 (cell 0x00788b6c, base 0x00788b70) with \'dmb ish\' around the store.'),
    ),
    dict(
        name='npb_23',
        method='NetPlayerButton -[setFrame:]',
        types='v24@0:4{CGRect={CGPoint=ff}{CGSize=ff}}8',
        start=7889560,
        end=7890168,
        disasm='disasm_worldtileloader_npb_23.txt',
        base_add=7889576,
        base_literal=7890164,
        boundary='ARM.exidx end 0x007864f8 (listing bound); next ObjC IMP 0x007864f8 NetPlayerButton -[updatedPlayerIfNeeded:]',
        selectors={
                 0x7864d0: (15208960, 'setFrame:'),
                 0x7864d8: (15208964, 'windowInfoChanged:'),
        },
        imports={
                 0x7864d4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7864dc: (17155636, 'OBJC_IVAR_$_MJView.windowInfo', 52),
                 0x7864e0: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
                 0x7864e4: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0x7864ec: (17159940, 'OBJC_IVAR_$_NetPlayerButton.avatarImage', 296),
                 0x7864f0: (17159976, 'OBJC_IVAR_$_NetPlayerButton.mutedImage', 300),
        },
        classes={
                 0x7864c8: (15252784, 'OBJC_CLASS_$_NetPlayerButton'),
        },
        instructions=[(7889560, 'push {r4, r5, r6, sl, fp, lr}'), (7890164, 'addeq sb, sp, r4, asr 16')],
        calls=[(7889724, 'bl loc.imp.objc_msgSendSuper2'), (7889848, 'bl 0x7853a8'), (7889956, 'bl loc.imp.objc_msgSend'), (7890052, 'bl loc.imp.objc_msgSend'), (7890108, 'blx lr')],
        branches=[],
        semantics=('NetPlayerButton -[setFrame:] @0x00786298 (152 words, 0 branches, 5 calls): CGRect in r2/r3 + stack. [super setFrame:rect] (objc_msgSendSuper2, class cell 0x007864c8); then packs self->frame (MJView.frame@8, pre-indexed ldr r1,[lr,r4]!) with bl 0x7853a8 and applies it verbatim (no inset) to avatarImage@296 and mutedImage@300 via objc_msgSend setFrame: (selector cell 0x007864d0); finally, if playerUI@292 != nil, [playerUI windowInfoChanged:self->windowInfo] (0x007864bc). No branches - straight-line 5-call layout path.'),
    ),
    dict(
        name='npb_24',
        method='NetPlayerButton -[setFrame:windowInfo:alignment:]',
        types='v32@0:4{CGRect={CGPoint=ff}{CGSize=ff}}8^{WindowInfo=ffffffff}24i28',
        start=7886232,
        end=7886948,
        disasm='disasm_worldtileloader_npb_24.txt',
        base_add=7886248,
        base_literal=7886944,
        boundary='ARM.exidx end 0x00785864 (listing bound); next ObjC IMP 0x00785864 NetPlayerButton -[renderFrame:projectionMatrix:]',
        selectors={
                 0x785838: (15208960, 'setFrame:'),
                 0x785840: (15208964, 'windowInfoChanged:'),
        },
        imports={
                 0x78583c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x785844: (17155636, 'OBJC_IVAR_$_MJView.windowInfo', 52),
                 0x785848: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
                 0x785850: (17159944, 'OBJC_IVAR_$_NetPlayerButton.alignment', 288),
                 0x785854: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0x785858: (17159940, 'OBJC_IVAR_$_NetPlayerButton.avatarImage', 296),
                 0x78585c: (17159976, 'OBJC_IVAR_$_NetPlayerButton.mutedImage', 300),
        },
        classes={
                 0x785830: (15252784, 'OBJC_CLASS_$_NetPlayerButton'),
        },
        instructions=[(7886232, 'push {r4, r5, r6, r7, fp, lr}'), (7886944, 'addeq sl, sp, r4, asr 10')],
        calls=[(7886412, 'bl loc.imp.objc_msgSendSuper2'), (7886624, 'bl 0x7853a8'), (7886732, 'bl loc.imp.objc_msgSend'), (7886828, 'bl loc.imp.objc_msgSend'), (7886884, 'blx lr')],
        branches=[],
        semantics=('NetPlayerButton -[setFrame:windowInfo:alignment:] @0x00785598 (179 words, 0 branches, 5 calls): CGRect + windowInfo + int alignment (32 bytes of args, fp = sp+0x10). [super setFrame:rect] via objc_msgSendSuper2 (0x0078564c); stores windowInfo into MJView.windowInfo@52 and alignment into alignment@288; packs CGRectInset(self->frame,4,4) (x+4,y+4,w-8,h-8, vmov #16/#32 = 4.0/8.0, helper bl 0x7853a8) and applies it to avatarImage@296 and mutedImage@300; finally if playerUI@292 != nil [playerUI windowInfoChanged:self->windowInfo] (0x00785824). Same call shape as setFrame: but with the 4-point inset and the explicit windowInfo/alignment writes.'),
    ),
    dict(
        name='npb_25',
        method='NetPlayerButton -[setIsAdmin:]',
        types='v12@0:4c8',
        start=7900208,
        end=7900276,
        disasm='disasm_worldtileloader_npb_25.txt',
        base_add=7900236,
        base_literal=7900272,
        boundary='ARM.exidx end 0x00788c74 (listing bound); next ObjC IMP 0x00788c74 NetPlayerButton -[isMod]',
        selectors={},
        imports={},
        ivars={
                 0x788c6c: (17159996, 'OBJC_IVAR_$_NetPlayerButton.isAdmin', 319),
        },
        classes={},
        instructions=[(7900208, 'sub sp, sp, 0xc'), (7900272, 'addeq r6, sp, r0, lsr 29')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[setIsAdmin:] @0x00788c30 (17 words, 0 calls): char setter - strb r2 to self+isAdmin@319 (cell 0x00788c6c, base 0x00788c70), dmb ish around the store.'),
    ),
    dict(
        name='npb_26',
        method='NetPlayerButton -[setIsMod:]',
        types='v12@0:4c8',
        start=7900336,
        end=7900404,
        disasm='disasm_worldtileloader_npb_26.txt',
        base_add=7900364,
        base_literal=7900400,
        boundary='ARM.exidx end 0x00788cf4 (listing bound); next ObjC IMP 0x00788cf4 NetPlayerButton -[cloudMode]',
        selectors={},
        imports={},
        ivars={
                 0x788cec: (17160000, 'OBJC_IVAR_$_NetPlayerButton.isMod', 320),
        },
        classes={},
        instructions=[(7900336, 'sub sp, sp, 0xc'), (7900400, 'addeq r6, sp, r0, lsr 28')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[setIsMod:] @0x00788cb0 (17 words, 0 calls): char setter - strb r2 to self+isMod@320 (cell 0x00788cec, base 0x00788cf0), dmb ish around the store.'),
    ),
    dict(
        name='npb_27',
        method='NetPlayerButton -[setIsOwner:]',
        types='v12@0:4c8',
        start=7900080,
        end=7900148,
        disasm='disasm_worldtileloader_npb_27.txt',
        base_add=7900108,
        base_literal=7900144,
        boundary='ARM.exidx end 0x00788bf4 (listing bound); next ObjC IMP 0x00788bf4 NetPlayerButton -[isAdmin]',
        selectors={},
        imports={},
        ivars={
                 0x788bec: (17159992, 'OBJC_IVAR_$_NetPlayerButton.isOwner', 318),
        },
        classes={},
        instructions=[(7900080, 'sub sp, sp, 0xc'), (7900144, 'addeq r6, sp, r0, lsr 30')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[setIsOwner:] @0x00788bb0 (17 words, 0 calls): char setter - strb r2 to self+isOwner@318 (cell 0x00788bec, base 0x00788bf0), dmb ish around the store.'),
    ),
    dict(
        name='npb_28',
        method='NetPlayerButton -[setLocal:]',
        types='v12@0:4c8',
        start=7899696,
        end=7899764,
        disasm='disasm_worldtileloader_npb_28.txt',
        base_add=7899724,
        base_literal=7899760,
        boundary='ARM.exidx end 0x00788a74 (listing bound); next ObjC IMP 0x00788a74 NetPlayerButton -[textChatEnabled]',
        selectors={},
        imports={},
        ivars={
                 0x788a6c: (17160008, 'OBJC_IVAR_$_NetPlayerButton.local', 305),
        },
        classes={},
        instructions=[(7899696, 'sub sp, sp, 0xc'), (7899760, 'addeq r7, sp, r0, lsr 1')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[setLocal:] @0x00788a30 (17 words, 0 calls): char setter - strb r2 to self+local@305 (cell 0x00788a6c, base 0x00788a70), dmb ish around the store.'),
    ),
    dict(
        name='npb_29',
        method='NetPlayerButton -[setMuted:]',
        types='v12@0:4c8',
        start=7900592,
        end=7900660,
        disasm='disasm_worldtileloader_npb_29.txt',
        base_add=7900620,
        base_literal=7900656,
        boundary='ARM.exidx end 0x00788df4 (listing bound); next ObjC IMP 0x00788f54 ProjectileManager -[initWithWorld:cache:]',
        selectors={},
        imports={},
        ivars={
                 0x788dec: (17159988, 'OBJC_IVAR_$_NetPlayerButton.muted', 321),
        },
        classes={},
        instructions=[(7900592, 'sub sp, sp, 0xc'), (7900656, 'addeq r6, sp, r0, lsr 26')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[setMuted:] @0x00788db0 (17 words, 0 calls): char setter - strb r2 to self+muted@321 (cell 0x00788dec, base 0x00788df0), dmb ish around the store.'),
    ),
    dict(
        name='npb_30',
        method='NetPlayerButton -[setTextChatEnabled:]',
        types='v12@0:4c8',
        start=7899824,
        end=7899892,
        disasm='disasm_worldtileloader_npb_30.txt',
        base_add=7899852,
        base_literal=7899888,
        boundary='ARM.exidx end 0x00788af4 (listing bound); next ObjC IMP 0x00788af4 NetPlayerButton -[connected]',
        selectors={},
        imports={},
        ivars={
                 0x788aec: (17159960, 'OBJC_IVAR_$_NetPlayerButton.textChatEnabled', 316),
        },
        classes={},
        instructions=[(7899824, 'sub sp, sp, 0xc'), (7899888, 'addeq r7, sp, r0, lsr 32')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[setTextChatEnabled:] @0x00788ab0 (17 words, 0 calls): char setter - strb r2 to self+textChatEnabled@316 (cell 0x00788aec, base 0x00788af0), dmb ish around the store.'),
    ),
    dict(
        name='npb_31',
        method='NetPlayerButton -[startTouch:]',
        types='c16@0:4{CGPoint=ff}8',
        start=7896324,
        end=7896564,
        disasm='disasm_worldtileloader_npb_31.txt',
        base_add=7896388,
        base_literal=7896548,
        boundary='ARM.exidx end 0x00787df4 (listing bound); next ObjC IMP 0x00787df4 NetPlayerButton -[moveTouch:]',
        selectors={
                 0x787de8: (15209040, 'startTouch:'),
        },
        imports={},
        ivars={
                 0x787dec: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
        },
        classes={
                 0x787de0: (15252784, 'OBJC_CLASS_$_NetPlayerButton'),
        },
        instructions=[(7896324, 'push {fp, lr}'), (7896560, 'addeq r7, sp, ip, asr sp')],
        calls=[(7896424, 'bl loc.imp.objc_msgSendSuper2'), (7896512, 'bl loc.imp.objc_msgSend')],
        branches=[(7896448, 'bne', 7896524), (7896520, 'b', 7896532)],
        semantics=('NetPlayerButton -[startTouch:] @0x00787d04 (60 words, 2 branches, 2 calls): point in r2/r3; r = [super startTouch:point] (objc_msgSendSuper2 with a stack-built {self, NetPlayerButton class cell 0x00787de0} struct at sp+0x10, selector cell 0x00787de8); if r == 0 it delegates: r = [self->playerUI@292 startTouch:point] via objc_msgSend (0x00787dc0). Returns r as a sign-extended byte; frame fp = sp, sub sp,#0x40.'),
    ),
    dict(
        name='npb_32',
        method='NetPlayerButton -[textChatEnabled]',
        types='c8@0:4',
        start=7899764,
        end=7899824,
        disasm='disasm_worldtileloader_npb_32.txt',
        base_add=7899772,
        base_literal=7899820,
        boundary='ARM.exidx end 0x00788ab0 (listing bound); next ObjC IMP 0x00788ab0 NetPlayerButton -[setTextChatEnabled:]',
        selectors={},
        imports={},
        ivars={
                 0x788aa8: (17159960, 'OBJC_IVAR_$_NetPlayerButton.textChatEnabled', 316),
        },
        classes={},
        instructions=[(7899764, 'sub sp, sp, 8'), (7899820, 'addeq r7, sp, r0, ror r0')],
        calls=[],
        branches=[],
        semantics=('NetPlayerButton -[textChatEnabled] @0x00788a74 (15 words, 0 calls): offset-cell getter, char textChatEnabled@316 (cell 0x00788aa8, base 0x00788aac), ldrsb.'),
    ),
    dict(
        name='npb_33',
        method='NetPlayerButton -[textToggleButtonTapped]',
        types='v8@0:4',
        start=7898296,
        end=7898672,
        disasm='disasm_worldtileloader_npb_33.txt',
        base_add=7898312,
        base_literal=7898668,
        boundary='ARM.exidx end 0x00788630 (listing bound); next ObjC IMP 0x00788630 NetPlayerButton -[muteButtonTapped]',
        selectors={
                 0x788610: (15209076, 'textToggleButtonTappedForButton:'),
                 0x78861c: (15209072, 'setBool:forKey:'),
                 0x788624: (15208912, 'standardUserDefaults'),
        },
        imports={
                 0x78860c: (17151904, 'objc_msgSend'),
                 0x788618: (16318744, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x788614: (17159952, 'OBJC_IVAR_$_NetPlayerButton.worldUI', 284),
                 0x788620: (17159960, 'OBJC_IVAR_$_NetPlayerButton.textChatEnabled', 316),
        },
        classes={
                 0x788628: (15246972, 'OBJC_CLASS_$_NSUserDefaults'),
        },
        instructions=[(7898296, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7898668, 'addeq r7, sp, r4, lsr 12')],
        calls=[(7898508, 'blx r3'), (7898584, 'blx lr'), (7898624, 'blx ip')],
        branches=[],
        semantics=('NetPlayerButton -[textToggleButtonTapped] @0x007884b8 (94 words, 0 branches, 3 calls): flips self->textChatEnabled@316 = !value (0x00788558), then persists the inverse to NSUserDefaults: [[NSUserDefaults standardUserDefaults] setBool:!self->textChatEnabled forKey:@"textChatDisabled"] (CFString 0xf90118, class cell 0x00788628, selector cells 0x0078861c/0x00788624; the NOT of the freshly stored value is recomputed at 0x007885b4 and sign-extended), then notifies the list: [self->worldUI textToggleButtonTappedForButton:self] (0x00788600). All three sends go through blx on saved register copies.'),
    ),
    dict(
        name='npb_34',
        method='NetPlayerButton -[touchIsInUI:]',
        types='c16@0:4{CGPoint=ff}8',
        start=7896084,
        end=7896324,
        disasm='disasm_worldtileloader_npb_34.txt',
        base_add=7896148,
        base_literal=7896308,
        boundary='ARM.exidx end 0x00787df4; body trimmed at the next IMP 0x00787d04 NetPlayerButton -[startTouch:]',
        selectors={
                 0x787cf8: (15209036, 'touchIsInUI:'),
        },
        imports={},
        ivars={
                 0x787cfc: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
        },
        classes={
                 0x787cf0: (15252784, 'OBJC_CLASS_$_NetPlayerButton'),
        },
        instructions=[(7896084, 'push {fp, lr}'), (7896320, 'addeq r7, sp, ip, asr 28')],
        calls=[(7896184, 'bl loc.imp.objc_msgSendSuper2'), (7896272, 'bl loc.imp.objc_msgSend')],
        branches=[(7896208, 'bne', 7896284), (7896280, 'b', 7896292)],
        semantics=('NetPlayerButton -[touchIsInUI:] @0x00787c14 (60 words, 2 branches, 2 calls, body trimmed at the next IMP 0x00787d04): same delegate pattern as startTouch: - r = [super touchIsInUI:point] via objc_msgSendSuper2 ({self, class cell 0x00787cf0}, selector cell 0x00787cf8, point in r2/r3); if r == 0 then r = [self->playerUI@292 touchIsInUI:point] via objc_msgSend (0x00787cd0); returns the sign-extended byte.'),
    ),
    dict(
        name='npb_35',
        method='NetPlayerButton -[updatedPlayerIfNeeded:]',
        types='v12@0:4@8',
        start=7890168,
        end=7896008,
        disasm='disasm_worldtileloader_npb_35.txt',
        base_add=7890184,
        base_literal=7893056,
        boundary='ARM.exidx end 0x00787bc8 (listing bound); next ObjC IMP 0x00787c14 NetPlayerButton -[touchIsInUI:]',
        selectors={
                 0x787048: (15208976, 'isEqualToString:'),
                 0x787054: (15208972, 'objectForKey:'),
                 0x787058: (15208984, 'retain'),
                 0x78705c: (15208980, 'autorelease'),
                 0x787074: (15208988, 'boolValue'),
                 0x7876e4: (15208992, 'playerIsMuted:'),
                 0x787920: (15209008, 'cloudMode'),
                 0x787924: (15209004, 'isMod'),
                 0x787928: (15209000, 'isAdmin'),
                 0x78792c: (15208996, 'isOwner'),
                 0x787b10: (15208972, 'objectForKey:'),
                 0x787b14: (15208984, 'retain'),
                 0x787b18: (15208980, 'autorelease'),
                 0x787b1c: (15208988, 'boolValue'),
                 0x787b34: (15209004, 'isMod'),
                 0x787b38: (15209012, 'setBackgroundTexture:'),
                 0x787b40: (15208920, 'textureNamed:'),
                 0x787b58: (15209016, 'setDisableBanButtons:'),
                 0x787b68: (15208952, 'release'),
                 0x787b70: (15209020, 'imageWithData:'),
                 0x787b78: (15209024, 'initWithUIImage:'),
                 0x787b7c: (15208936, 'alloc'),
                 0x787b94: (15208940, 'initWithFrame:cache:windowInfo:texture:'),
                 0x787ba4: (15209028, 'uppercaseString'),
                 0x787bb4: (15209032, 'setColor:'),
                 0x787bc4: (15208964, 'windowInfoChanged:'),
        },
        imports={
                 0x787044: (17151904, 'objc_msgSend'),
                 0x787050: (16318888, '__CFConstantStringClassReference'),
                 0x787060: (16318984, '__CFConstantStringClassReference'),
                 0x787064: (16318968, '__CFConstantStringClassReference'),
                 0x787068: (16318920, '__CFConstantStringClassReference'),
                 0x78706c: (16318952, '__CFConstantStringClassReference'),
                 0x787070: (16318936, '__CFConstantStringClassReference'),
                 0x787078: (16318904, '__CFConstantStringClassReference'),
                 0x7876dc: (16319000, '__CFConstantStringClassReference'),
                 0x787b0c: (17151904, 'objc_msgSend'),
                 0x787b3c: (16318728, '__CFConstantStringClassReference'),
                 0x787b48: (16319064, '__CFConstantStringClassReference'),
                 0x787b4c: (16319048, '__CFConstantStringClassReference'),
                 0x787b50: (16319032, '__CFConstantStringClassReference'),
                 0x787b54: (16319016, '__CFConstantStringClassReference'),
                 0x787b6c: (16319080, '__CFConstantStringClassReference'),
                 0x787b9c: (16318856, '__CFConstantStringClassReference'),
                 0x787ba8: (16319096, '__CFConstantStringClassReference'),
                 0x787bac: (16319112, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x78704c: (17159984, 'OBJC_IVAR_$_NetPlayerButton.playerID', 308),
                 0x7876e0: (17159988, 'OBJC_IVAR_$_NetPlayerButton.muted', 321),
                 0x7876e8: (17159948, 'OBJC_IVAR_$_NetPlayerButton.world', 280),
                 0x787910: (17159992, 'OBJC_IVAR_$_NetPlayerButton.isOwner', 318),
                 0x787914: (17159996, 'OBJC_IVAR_$_NetPlayerButton.isAdmin', 319),
                 0x787918: (17160000, 'OBJC_IVAR_$_NetPlayerButton.isMod', 320),
                 0x78791c: (17159956, 'OBJC_IVAR_$_NetPlayerButton.cloudMode', 324),
                 0x787b20: (17159948, 'OBJC_IVAR_$_NetPlayerButton.world', 280),
                 0x787b24: (17159992, 'OBJC_IVAR_$_NetPlayerButton.isOwner', 318),
                 0x787b28: (17159996, 'OBJC_IVAR_$_NetPlayerButton.isAdmin', 319),
                 0x787b2c: (17160000, 'OBJC_IVAR_$_NetPlayerButton.isMod', 320),
                 0x787b30: (17159956, 'OBJC_IVAR_$_NetPlayerButton.cloudMode', 324),
                 0x787b44: (17155620, 'OBJC_IVAR_$_MJView.cache', 48),
                 0x787b5c: (17159980, 'OBJC_IVAR_$_NetPlayerButton.playerUI', 292),
                 0x787b60: (17160004, 'OBJC_IVAR_$_NetPlayerButton.hasAvatar', 304),
                 0x787b64: (17159940, 'OBJC_IVAR_$_NetPlayerButton.avatarImage', 296),
                 0x787b84: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0x787b90: (17155636, 'OBJC_IVAR_$_MJView.windowInfo', 52),
                 0x787ba0: (17159972, 'OBJC_IVAR_$_NetPlayerButton.playerName', 312),
                 0x787bb0: (17159964, 'OBJC_IVAR_$_NetPlayerButton.connected', 317),
                 0x787bc0: (17160008, 'OBJC_IVAR_$_NetPlayerButton.local', 305),
        },
        classes={
                 0x787b74: (15246984, 'OBJC_CLASS_$_UIImage'),
                 0x787b80: (15246988, 'OBJC_CLASS_$_CPTexture2D'),
                 0x787b8c: (15246980, 'OBJC_CLASS_$_MJImageView'),
        },
        instructions=[(7890168, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7896004, 'invalid')],
        calls=[(7890272, 'blx ip'), (7890316, 'blx r3'), (7890408, 'blx r2'), (7890440, 'blx r3'), (7890660, 'blx r4'), (7890676, 'blx r2'), (7890704, 'blx r3'), (7890724, 'blx r3'), (7890752, 'blx r3'), (7890772, 'blx r3'), (7890800, 'blx r3'), (7890820, 'blx r3'), (7890864, 'blx r3'), (7890884, 'blx r3'), (7890996, 'blx lr'), (7891016, 'blx r3'), (7891132, 'blx r3'), (7891684, 'blx r3'), (7891740, 'blx ip'), (7891796, 'blx ip'), (7891852, 'blx ip'), (7892020, 'blx ip'), (7892052, 'blx r3'), (7892236, 'blx ip'), (7892268, 'blx r3'), (7892452, 'blx ip'), (7892484, 'blx r3'), (7892668, 'blx ip'), (7892700, 'blx r3'), (7892808, 'blx ip'), (7892840, 'blx r3'), (7892916, 'blx r2'), (7893048, 'blx ip'), (7893196, 'blx ip'), (7893380, 'blx lr'), (7893420, 'blx r3'), (7893548, 'blx r3'), (7893660, 'blx r3'), (7893680, 'blx r3'), (7893696, 'blx r2'), (7893864, 'bl 0x7853a8'), (7893888, 'bl loc.imp.objc_msgSend'), (7894024, 'bl loc.imp.objc_msgSend'), (7894232, 'bl loc.imp.objc_msgSend'), (7894328, 'bl 0x7853a8'), (7894352, 'bl loc.imp.objc_msgSend'), (7894484, 'bl loc.imp.objc_msgSend'), (7894656, 'blx r3'), (7894680, 'blx r3'), (7894696, 'blx r2'), (7894712, 'blx r2'), (7894904, 'blx lr'), (7894920, 'blx r2'), (7895120, 'bl 0x787bc8'), (7895196, 'bl loc.imp.objc_msgSend'), (7895256, 'bl 0x787bc8'), (7895304, 'bl loc.imp.objc_msgSend'), (7895392, 'bl 0x787bc8'), (7895468, 'bl loc.imp.objc_msgSend'), (7895536, 'bl 0x787bc8'), (7895584, 'bl loc.imp.objc_msgSend'), (7895808, 'blx r3')],
        branches=[(7890332, 'bne', 7890464), (7890896, 'beq', 7890912), (7890908, 'b', 7891044), (7891028, 'beq', 7891040), (7891040, 'b', 7891044), (7891168, 'beq', 7891212), (7891248, 'bne', 7891372), (7891288, 'bne', 7891372), (7891328, 'bne', 7891372), (7891368, 'beq', 7891496), (7891504, 'beq', 7891884), (7891916, 'beq', 7892060), (7892056, 'b', 7892856), (7892092, 'beq', 7892276), (7892132, 'bne', 7892276), (7892272, 'b', 7892852), (7892308, 'beq', 7892492), (7892348, 'beq', 7892492), (7892488, 'b', 7892848), (7892524, 'beq', 7892708), (7892564, 'beq', 7892708), (7892704, 'b', 7892844), (7892844, 'b', 7892848), (7892848, 'b', 7892852), (7892852, 'b', 7892856), (7892928, 'beq', 7893204), (7892964, 'beq', 7893116), (7893052, 'b', 7893200), (7893200, 'b', 7893204), (7893236, 'beq', 7893252), (7893248, 'bne', 7894820), (7893480, 'beq', 7894080), (7893568, 'beq', 7894076), (7893716, 'beq', 7894072), (7894072, 'b', 7894076), (7894076, 'b', 7894080), (7894112, 'bne', 7894508), (7894152, 'bne', 7894508), (7894516, 'bne', 7894764), (7894744, 'b', 7894816), (7894800, 'beq', 7894812), (7894812, 'b', 7894816), (7894816, 'b', 7894820), (7894940, 'bne', 7894964), (7895012, 'beq', 7895024), (7895076, 'beq', 7895344), (7895308, 'b', 7895588), (7895624, 'beq', 7895708), (7895664, 'beq', 7895676), (7895716, 'beq', 7895812)],
        semantics=('NetPlayerButton -[updatedPlayerIfNeeded:] @0x007864f8 (1460 words, 50 branches, 62 calls; [census] grade): refreshes one row from a per-player NSDictionary (arg at fp-0x28). Head: pid = [d objectForKey:@"playerID"] (0xf901a8); if ![self->playerID isEqualToString:pid] the ivar is replaced with the ARC strong-store form ([old autorelease] + [pid retain]). Then reads flags = [[d objectForKey:key] boolValue] for keys local/owner/admin/mod (0xf901b8/0xf901d8/0xf901e8/0xf901c8) and mode-sentinel cloudMode = 0xA8F4 if [[d objectForKey:@"supermod"] (0xf901f8) isEqualToString:@"mode1"] (0xf90208), 0x4D83 if isEqualToString:@"mode2"] (0xf90218), else 0. Muted sync: [self->world playerIsMuted:pid] compared with self->muted@321, on change writes muted + changed flag. Role diff: if isOwner/isAdmin/isMod/cloudMode differ from current, all four ivars (318/319/320/324) are rewritten and changed=1. Local-row block (only when local==1): re-syncs isOwner/isAdmin/isMod/cloudMode from live World sends ([self->world isOwner/isAdmin/isMod/cloudMode]) and forces changed=1. Background texture chain via [self->cache textureNamed:] + setBackgroundTexture: - owner: InventoryButtonBackgroundOwner.png (0xf90228); admin+cloudMode 0xA8F4: ...ModRed.png (0xf90238); admin otherwise: ...Admin.png (0xf90248); mod (and not cloudMode 0x4D83): ...Mod.png (0xf90258); default: InventoryButtonBackground.png (0xf90108); cloudMode 0x4D83 maps admin/mod to the default. If [self->world isMod], tells the popup [self->playerUI setDisableBanButtons:self->isMod]. Avatar: rebuilds when the playerID changed or hasAvatar@304 is false - releases and nils avatarImage@296, photo = [d objectForKey:@"photo"] (0xf90268) -> [UIImage imageWithData:] -> [[CPTexture2D alloc] initWithUIImage:] autoreleased -> avatarImage = [[MJImageView alloc] initWithFrame:CGRectInset(self->frame,4,4) cache/windowInfo/texture] and hasAvatar=1; when no photo exists it falls back to textureNamed:@"noGCAvatar.png" (0xf90188). Name: when the ID did not change it replaces playerName@312 with [[[d objectForKey:@"alias"] (0xf90278) uppercaseString] retain] after releasing the old value. Connected: conn = [[d objectForKey:@"connected"] (0xf90288) boolValue], falling back to self->local when false; writes connected@317 and colours the row with the 4-float helper 0x00787bc8 - connected: self setColor:{1,1,1,1} and avatarImage setColor:{1,1,1,1} (0x3f800000); disconnected: self {0.1,0.1,0.1,1.0} (0x3dcccccd) and avatarImage {0.2,0.2,0.2,0.5} (0x3e4ccccd/0x3f000000). Finally a local-flag diff sets changed and, when changed is set, one [self->playerUI windowInfoChanged:self->windowInfo] is sent (0x00787b00). Call histogram: 47 blx rN (indirect objc_msgSend family), 9 bl loc.imp.objc_msgSend, 4 bl 0x787bc8 (float4/colour packer), 2 bl 0x7853a8 (CGRect packer).'),
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
        'batch': 'NetPlayerButton (E156): the multiplayer player-row button; 36 bodies',
        'claim': ('\'the per-player row button surface (touch cycle, button dispatch, the mute/ban/kick/report actions, the chat toggle and the player-state refresh); the surrounding player-list UI is outside these bodies\''),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'netplayerbutton.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale netplayerbutton.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
