#!/usr/bin/env python3
"""Hash-gated recovery of the MultiplayerWorldOptionsUI (E158).

The multiplayer world options screen lands: the batch sweeps the options-overlay surface:
35 bodies, {total} instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLDOPTIONS.md for the prose and boundaries.
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
    'bl 0x4f05dc': 0x004f05dc,
    'bl 0x4f0734': 0x004f0734,
    'bl 0x4f0780': 0x004f0780,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.drawShaderQuad': 0x007c43dc,
    'bl sym.drawShaderQuadNoTexture': 0x007c4790,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisable': 0x001c2c48,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0x001c3d58,
    'bl sym.imp.__wrap_glEnable': 0x001c2b04,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
}

SPECS = [
    dict(
        name='mwou_00',
        method='MultiplayerWorldOptionsUI -[.cxx_construct]',
        types='@8@0:4',
        start=5199732,
        end=5199756,
        disasm='disasm_worldtileloader_mwou_00.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004f578c (listing bound); next ObjC IMP 0x004f58ec VinePlant -[objectType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5199732, 'sub sp, sp, 8'), (5199752, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[.cxx_construct] @0x004f5774 (6 words, 0 branches, 0 calls; read) - empty Apportable C++-construct stub. Frame \'sub sp,sp,#8\'; spills r0(self)/r1(_cmd) to [sp,4]/[sp], re-loads r0 from the self slot, restores sp and returns via \'bx lr\'. No constant pool, no ivar write and no message send: the class has no C++ reference-typed ivars, so the value returned is just the receiver.'),
    ),
    dict(
        name='mwou_01',
        method='MultiplayerWorldOptionsUI -[IAPForWorldTopupSucceeeded:transactionID:]',
        types='v16@0:4@8@12',
        start=5198980,
        end=5199096,
        disasm='disasm_worldtileloader_mwou_01.txt',
        base_add=5198996,
        base_literal=5199092,
        boundary='ARM.exidx end 0x004f54f8 (listing bound); next ObjC IMP 0x004f54f8 MultiplayerWorldOptionsUI -[cloudTopupSucceeded:]',
        selectors={
                 0x4f54ec: (15193760, 'IAPForWorldTopupSucceeeded:transactionID:'),
        },
        imports={
                 0x4f54e8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f54f0: (17155464, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI', 12),
        },
        classes={},
        instructions=[(5198980, 'push {r4, r5, fp, lr}'), (5199092, 'adcseq sl, r6, r8, asr r6')],
        calls=[(5199068, 'blx lr')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[IAPForWorldTopupSucceeeded:transactionID:] @0x004f5484 (29 words, 0 branches, 1 call; read) - one-send pass-through to the in-app-purchase child view. PIC base 0x0105faf4 (own cell 0x004f54f4 = 0xb6a658, add-pc at 0x004f5494). objc_msgSend from GOT 0x0105b7a0 (cell 0x004f54e8); addCreditUI offset cell 0x004f54f0 -> GOT 0x0105c588 (OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI, offset 12); selref 0x004f54ec -> 0x00e7d6a0 @selector(IAPForWorldTopupSucceeeded:transactionID:). Frame push {r4,r5,fp,lr} / add fp,sp,#8 / sub sp,#0x10; types v16@0:4@8@12 so the two object args arrive in r2/r3, get spilled to [sp,4]/[sp] and are re-loaded into r2/r3 after the receiver is built. Net: objc_msgSend(self->addCreditUI, IAPForWorldTopupSucceeeded:transactionID:, arg1, arg2); the delegated result is left in r0 (declared void).'),
    ),
    dict(
        name='mwou_02',
        method='MultiplayerWorldOptionsUI -[OKButton:]',
        types='v12@0:4@8',
        start=5191020,
        end=5191124,
        disasm='disasm_worldtileloader_mwou_02.txt',
        base_add=5191036,
        base_literal=5191120,
        boundary='ARM.exidx end 0x004f35d4 (listing bound); next ObjC IMP 0x004f35d4 MultiplayerWorldOptionsUI -[pvpButton:]',
        selectors={
                 0x4f35c8: (15193648, 'dismissMultiplayerWorldOptions'),
        },
        imports={
                 0x4f35c4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f35cc: (17155380, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.optionsUI', 8),
        },
        classes={},
        instructions=[(5191020, 'push {r4, sl, fp, lr}'), (5191120, 'adcseq ip, r6, r0, ror r5')],
        calls=[(5191096, 'blx ip')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[OKButton:] @0x004f356c (26 words, 0 branches, 1 call; read) - the panel\'s OK button action, forwarded to the owning options UI. Frame push {r4,sl,fp,lr} / add fp,sp,#8 / sub sp,#0x10; base 0x0105faf4 from cell 0x004f35d0 (0xb6c570 + add-pc at 0x004f357c). Single send objc_msgSend(self->optionsUI@8, @selector(dismissMultiplayerWorldOptions)) - offset cell 0x004f35cc -> GOT 0x0105c534, selref 0x004f35c8 -> 0x00e7d630, objc_msgSend GOT 0x0105b7a0. The sender argument (types v12@0:4@8, arrives in r2) is spilled to [sp,4] and never re-loaded, so the button pointer is dead: the action ignores which control fired it and unconditionally tells optionsUI to dismiss.'),
    ),
    dict(
        name='mwou_03',
        method='MultiplayerWorldOptionsUI -[addCreditButton:]',
        types='v12@0:4@8',
        start=5195576,
        end=5196356,
        disasm='disasm_worldtileloader_mwou_03.txt',
        base_add=5195592,
        base_literal=5196352,
        boundary='ARM.exidx end 0x004f4a44 (listing bound); next ObjC IMP 0x004f4a44 MultiplayerWorldOptionsUI -[dismissAddCreditUI]',
        selectors={
                 0x4f4a08: (15193504, 'canAddWorldCredit'),
                 0x4f4a10: (15193508, 'setEnabled:'),
                 0x4f4a20: (15193728, 'initWithWorldName:worldID:creditTimeString:windowInfo:cache:delegate:'),
                 0x4f4a2c: (15193724, 'getCurrentCreditTimeString'),
                 0x4f4a30: (15193720, 'saveID'),
                 0x4f4a34: (15193716, 'worldName'),
                 0x4f4a38: (15193436, 'alloc'),
        },
        imports={
                 0x4f4a04: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f4a0c: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
                 0x4f4a14: (17155416, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditButton', 140),
                 0x4f4a18: (17155464, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI', 12),
                 0x4f4a1c: (17155476, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.shouldDismissPauseUIOnExit', 172),
                 0x4f4a24: (17155372, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.cache', 116),
                 0x4f4a28: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
        },
        classes={
                 0x4f4a3c: (15245092, 'OBJC_CLASS_$_AddCreditUI'),
        },
        instructions=[(5195576, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5196352, 'adcseq fp, r6, r4, lsr 7')],
        calls=[(5195656, 'blx ip'), (5195752, 'blx ip'), (5195992, 'blx r2'), (5196040, 'blx ip'), (5196088, 'blx ip'), (5196136, 'blx ip'), (5196260, 'blx lr')],
        branches=[(5195668, 'bne', 5195760), (5195756, 'b', 5196284), (5195824, 'bne', 5196284)],
        semantics=('MultiplayerWorldOptionsUI -[addCreditButton:] @0x004f4738 (195 words, 3 branches, 7 calls; read) - the world-credit top-up entry point. Frame push {r4-r8,sl,fp,lr}/add fp,sp,#0x18/sub sp,#0x70; base 0x0105faf4 (cell 0x004f4a40 = 0xb6b3a4 + add-pc 0x004f4748). (A) Gate 0x004f4770-0x004f4794: r0 = objc_msgSend(self->world@4, @selector(canAddWorldCredit)) (offset cell 0x004f4a0c -> GOT 0x0105c524, selref 0x004f4a08 -> 0x00e7d5a0), then \'sxtb r0,r0; cmp r0,#0; bne 0x004f47f0\'. (B) refusal arm 0x004f4798-0x004f47ec: sends objc_msgSend(self->addCreditButton@140, @selector(setEnabled:), NO) (offset cell 0x004f4a14 -> GOT 0x0105c558, selref 0x004f4a10 -> 0x00e7d5a4) and jumps to the epilogue - i.e. no world credit, so the button is disabled. (C) allowed arm 0x004f47f0: first \'movw r3,#0; strb r3,[self+172]\' clears shouldDismissPauseUIOnExit (offset cell 0x004f4a1c -> GOT 0x0105c594), then a re-entrancy guard \'if (self->addCreditUI@12 != nil) bne epilogue\' (cell 0x004f4a18 -> GOT 0x0105c588). (D) build 0x004f4834-0x004f49f8: [[AddCreditUI alloc] initWithWorldName:worldName worldID:saveID creditTimeString:[self->world getCurrentCreditTimeString] windowInfo:self->windowInfo@112 cache:self->cache@116 delegate:self] with the receiver class from cell 0x004f4a3c -> 0x00e89f24 (OBJC_CLASS_$_AddCreditUI), selrefs alloc 0x00e7d55c, worldName 0x00e7d674, saveID 0x00e7d678, getCurrentCreditTimeString 0x00e7d67c and initWithWorldName:worldID:creditTimeString:windowInfo:cache:delegate: 0x00e7d680; the three strings are produced by separate nested sends on self->world and the 6 arguments are marshalled as r2,r3 plus four stack words. The result is stored back into self->addCreditUI@12 at 0x004f49f8.'),
    ),
    dict(
        name='mwou_04',
        method='MultiplayerWorldOptionsUI -[alertView:didDismissWithButtonIndex:]',
        types='v16@0:4@8i12',
        start=5192720,
        end=5193608,
        disasm='disasm_worldtileloader_mwou_04.txt',
        base_add=5192736,
        base_literal=5193604,
        boundary='ARM.exidx end 0x004f3f88 (listing bound); next ObjC IMP 0x004f3f88 MultiplayerWorldOptionsUI -[textFieldShouldReturn:]',
        selectors={
                 0x4f3f54: (15193672, 'length'),
                 0x4f3f58: (15193668, 'text'),
                 0x4f3f5c: (15193568, 'textFieldAtIndex:'),
                 0x4f3f60: (15193508, 'setEnabled:'),
                 0x4f3f68: (15193492, 'setOn:'),
                 0x4f3f70: (15193536, 'serverPassword'),
                 0x4f3f78: (15193676, 'sendNewPasswordToServer:'),
                 0x4f3f7c: (15193576, 'autorelease'),
                 0x4f3f80: (15193572, 'setDelegate:'),
        },
        imports={
                 0x4f3f50: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f3f4c: (17155460, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.textEntryAlertView', 168),
                 0x4f3f64: (17155444, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordSetButton', 156),
                 0x4f3f6c: (17155428, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordToggleButton', 152),
                 0x4f3f74: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={},
        instructions=[(5192720, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5193604, 'adcseq fp, r6, ip, asr 29')],
        calls=[(5192916, 'blx r4'), (5192940, 'blx r2'), (5192964, 'blx r2'), (5193148, 'blx sl'), (5193184, 'blx r3'), (5193252, 'blx r3'), (5193296, 'blx ip'), (5193412, 'blx r3'), (5193432, 'blx r3'), (5193472, 'blx r3'), (5193508, 'blx r3')],
        branches=[(5192792, 'bne', 5193540), (5192804, 'bne', 5193300), (5192972, 'bne', 5192984)],
        semantics=('MultiplayerWorldOptionsUI -[alertView:didDismissWithButtonIndex:] @0x004f3c10 (222 words, 3 branches, 11 calls; read) - the UIAlertView delegate callback for the password-entry alert, a two-level dispatch. Frame push {r4-r8,sl,fp,lr}/add fp,sp,#0x18/sub sp,#0x80; base 0x0105faf4 (cell 0x004f3f84 = 0xb6becc + add-pc 0x004f3c20). (A) Filter 0x004f3c3c: \'cmp alertView, self->textEntryAlertView@168\' (cell 0x004f3f4c -> GOT 0x0105c584) with \'bne 0x004f3f44\' throwing every other alert away. (B) \'cmp buttonIndex,#1; bne 0x004f3e54\' splits commit from cancel. (C) commit arm 0x004f3c68-0x004f3e50: text = [[self->textEntryAlertView textFieldAtIndex:0] text] (selrefs 0x00e7d5e0 / 0x00e7d644); \'if ([text length] == 0) text = nil\' (selref length 0x00e7d648, \'cmp r0,#0; bne\' + movw r0,#0 store at [fp,-0x30]); then [self->world sendNewPasswordToServer:text] (selref 0x00e7d64c), then BOOL pw = ([self->world serverPassword] != nil) computed by \'movw r0,#0; movne r0,#1; and r0,r0,#1\' (selref 0x00e7d5c0) and applied twice: [self->passwordToggleButton@152 setOn:pw] (cell 0x004f3f6c -> GOT 0x0105c564, selref 0x00e7d594) and [self->passwordSetButton@156 setEnabled:pw] (cell 0x004f3f64 -> GOT 0x0105c574, selref 0x00e7d5a4). (D) cancel/other arm 0x004f3e54-0x004f3f40 tears the alert down: [self->textEntryAlertView textFieldAtIndex:0] -> setDelegate:nil -> [self->textEntryAlertView setDelegate:nil] -> [self->textEntryAlertView autorelease] (selrefs 0x00e7d5e4 / 0x00e7d5e8) -> self->textEntryAlertView = nil.'),
    ),
    dict(
        name='mwou_05',
        method='MultiplayerWorldOptionsUI -[appDatabase]',
        types='@8@0:4',
        start=5199532,
        end=5199632,
        disasm='disasm_worldtileloader_mwou_05.txt',
        base_add=5199548,
        base_literal=5199628,
        boundary='ARM.exidx end 0x004f5774; body trimmed at the next IMP 0x004f5710 MultiplayerWorldOptionsUI -[iapCancelled]',
        selectors={
                 0x4f5704: (15193780, 'appDatabase'),
        },
        imports={
                 0x4f5700: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f5708: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={},
        instructions=[(5199532, 'push {fp, lr}'), (5199628, 'adcseq sl, r6, r0, lsr r4')],
        calls=[(5199604, 'blx r3')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[appDatabase] @0x004f56ac (25 words, 0 branches, 1 call; read; roster-trimmed body) - trivial one-send forward: objc_msgSend(self->world@4, @selector(appDatabase)). Frame push {fp,lr}/mov fp,sp/sub sp,#8; self is spilled to [sp,4] and re-read at 0x004f56e0, offset cell 0x004f5708 -> GOT 0x0105c524 (OBJC_IVAR_$_MultiplayerWorldOptionsUI.world, offset 4), selref 0x004f5704 -> 0x00e7d6b4, objc_msgSend GOT 0x0105b7a0 (cell 0x004f5700); base 0x0105faf4 from cell 0x004f570c (0xb6a430 + add-pc 0x004f56bc). Pure delegation to the World object, no caching and no state of its own.'),
    ),
    dict(
        name='mwou_06',
        method='MultiplayerWorldOptionsUI -[cloudInterface]',
        types='@8@0:4',
        start=5199432,
        end=5199532,
        disasm='disasm_worldtileloader_mwou_06.txt',
        base_add=5199448,
        base_literal=5199528,
        boundary='ARM.exidx end 0x004f5774; body trimmed at the next IMP 0x004f56ac MultiplayerWorldOptionsUI -[appDatabase]',
        selectors={
                 0x4f56a0: (15193776, 'cloudInterface'),
        },
        imports={
                 0x4f569c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f56a4: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={},
        instructions=[(5199432, 'push {fp, lr}'), (5199528, 'umlalseq sl, r6, r4, r4')],
        calls=[(5199504, 'blx r3')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[cloudInterface] @0x004f5648 (25 words, 0 branches, 1 call; read; roster-trimmed body) - byte-for-byte the same accessor shape as -[appDatabase]: objc_msgSend(self->world@4, @selector(cloudInterface)) with the identical base cell idiom (cell 0x004f56a8 = 0xb6a494 + add-pc 0x004f5658 -> 0x0105faf4), the same self->world offset cell 0x004f56a4 -> GOT 0x0105c524 and the same objc_msgSend GOT 0x0105b7a0 (cell 0x004f569c); only the selref differs (0x004f56a0 -> 0x00e7d6b0, @selector(cloudInterface)). The class therefore owns no cloud handle of its own - both appDatabase and the cloud interface are fetched from the world each time.'),
    ),
    dict(
        name='mwou_07',
        method='MultiplayerWorldOptionsUI -[cloudTopupFailed:]',
        types='v12@0:4i8',
        start=5199224,
        end=5199332,
        disasm='disasm_worldtileloader_mwou_07.txt',
        base_add=5199240,
        base_literal=5199328,
        boundary='ARM.exidx end 0x004f55e4 (listing bound); next ObjC IMP 0x004f55e4 MultiplayerWorldOptionsUI -[iapStarted]',
        selectors={
                 0x4f55d8: (15193768, 'cloudTopupFailed:'),
        },
        imports={
                 0x4f55d4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f55dc: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={},
        instructions=[(5199224, 'push {r4, sl, fp, lr}'), (5199328, 'adcseq sl, r6, r4, ror 10')],
        calls=[(5199304, 'blx ip')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[cloudTopupFailed:] @0x004f5578 (27 words, 0 branches, 1 call; read) - one-send pass-through of the top-up failure code. Frame push {r4,sl,fp,lr}/add fp,sp,#8/sub sp,#0x10; base 0x0105faf4 from cell 0x004f55e0 (0xb6a564 + add-pc 0x004f5588). types v12@0:4i8 so the failure code arrives as an int in r2; the code spills r0-r3 to [sp,0xc]/[sp,8]/[sp,4]/[sp] and re-loads r2 from [sp,4] before the send. Single send objc_msgSend(self->world@4, @selector(cloudTopupFailed:), code) - offset cell 0x004f55dc -> GOT 0x0105c524, selref 0x004f55d8 -> 0x00e7d6a8, objc_msgSend GOT 0x0105b7a0.'),
    ),
    dict(
        name='mwou_08',
        method='MultiplayerWorldOptionsUI -[cloudTopupSucceeded:]',
        types='v12@0:4f8',
        start=5199096,
        end=5199224,
        disasm='disasm_worldtileloader_mwou_08.txt',
        base_add=5199112,
        base_literal=5199220,
        boundary='ARM.exidx end 0x004f5578 (listing bound); next ObjC IMP 0x004f5578 MultiplayerWorldOptionsUI -[cloudTopupFailed:]',
        selectors={
                 0x4f556c: (15193764, 'cloudTopupSucceeded:'),
        },
        imports={
                 0x4f5568: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f5570: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={},
        instructions=[(5199096, 'push {fp, lr}'), (5199220, 'adcseq sl, r6, r4, ror 11')],
        calls=[(5199196, 'blx r3')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[cloudTopupSucceeded:] @0x004f54f8 (32 words, 0 branches, 1 call; read) - one-send pass-through of the credited amount. types v12@0:4f8, so the float argument arrives as a bit pattern in r2: \'vmov s0,r2\' at 0x004f550c, \'vstr s0,[sp,4]\' at 0x004f5530 and a re-load \'vldr s0,[sp,4]; vmov r3,s0; mov r2,r3\' at 0x004f5544-0x004f5554 rebuild the outgoing argument register. Base 0x0105faf4 from cell 0x004f5574 (0xb6a5e4 + add-pc 0x004f5508); objc_msgSend GOT 0x0105b7a0 (cell 0x004f5568); self->world@4 offset cell 0x004f5570 -> GOT 0x0105c524; selref 0x004f556c -> 0x00e7d6a4. Net: objc_msgSend(self->world, @selector(cloudTopupSucceeded:), amount).'),
    ),
    dict(
        name='mwou_09',
        method='MultiplayerWorldOptionsUI -[customRulesButton:]',
        types='v12@0:4@8',
        start=5198436,
        end=5198784,
        disasm='disasm_worldtileloader_mwou_09.txt',
        base_add=5198452,
        base_literal=5198780,
        boundary='ARM.exidx end 0x004f53c0 (listing bound); next ObjC IMP 0x004f53c0 MultiplayerWorldOptionsUI -[dismissCustomRules]',
        selectors={
                 0x4f53a4: (15193560, 'initWithWorld:windowInfo:cache:parentUI:'),
                 0x4f53b4: (15193436, 'alloc'),
        },
        imports={
                 0x4f53a0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f539c: (17155432, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customGameRulesUI', 180),
                 0x4f53a8: (17155372, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.cache', 116),
                 0x4f53ac: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
                 0x4f53b0: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={
                 0x4f53b8: (15245084, 'OBJC_CLASS_$_CustomGameRulesUI'),
        },
        instructions=[(5198436, 'push {r4, r5, r6, r7, fp, lr}'), (5198780, 'adcseq sl, r6, r8, ror r8')],
        calls=[(5198616, 'blx r2'), (5198716, 'blx lr')],
        branches=[(5198504, 'bne', 5198740)],
        semantics=('MultiplayerWorldOptionsUI -[customRulesButton:] @0x004f5264 (87 words, 1 branch, 2 calls; read) - lazy creation of the custom-game-rules child UI, guarded by an existence check. Frame push {r4-r7,fp,lr}/add fp,sp,#0x10/sub sp,#0x38; base 0x0105faf4 from cell 0x004f53bc (0xb6a878 + add-pc 0x004f5274). (A) Guard 0x004f5278-0x004f52a8: \'movw ip,#0; r0 = self->customGameRulesUI@180; cmp r0, ip; bne 0x004f5394\' (offset cell 0x004f539c -> GOT 0x0105c568) - if the child UI already exists the action is a no-op. (B) Build 0x004f52ac-0x004f5390: [[CustomGameRulesUI alloc] initWithWorld:self->world@4 windowInfo:self->windowInfo@112 cache:self->cache@116 parentUI:self] - class from cell 0x004f53b8 -> 0x00e89f1c (OBJC_CLASS_$_CustomGameRulesUI), selrefs alloc 0x00e7d55c and initWithWorld:windowInfo:cache:parentUI: 0x00e7d5d8, offset cells 0x004f53b0/0x004f53ac/0x004f53a8 -> GOT 0x0105c524/0x0105c530/0x0105c52c, and the 4th argument is self itself (forwarded as parentUI). The single branch is the pre-send nil test, and the object is written to self->customGameRulesUI@180 at 0x004f5390.'),
    ),
    dict(
        name='mwou_10',
        method='MultiplayerWorldOptionsUI -[dealloc]',
        types='v8@0:4',
        start=5179948,
        end=5180872,
        disasm='disasm_worldtileloader_mwou_10.txt',
        base_add=5179964,
        base_literal=5180868,
        boundary='ARM.exidx end 0x004f0dc8 (listing bound); next ObjC IMP 0x004f0dc8 MultiplayerWorldOptionsUI -[windowInfoChanged:]',
        selectors={
                 0x4f0d78: (15193588, 'dealloc'),
                 0x4f0d84: (15193584, 'release'),
                 0x4f0d90: (15193564, 'dismissAlertViews'),
        },
        imports={
                 0x4f0d74: (17151900, 'objc_msgSendSuper2'),
                 0x4f0d80: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f0d88: (17155432, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customGameRulesUI', 180),
                 0x4f0d8c: (17155464, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI', 12),
                 0x4f0d94: (17155452, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customRulesButton', 164),
                 0x4f0d98: (17155448, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.ownerPortalButton', 160),
                 0x4f0d9c: (17155416, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditButton', 140),
                 0x4f0da0: (17155444, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordSetButton', 156),
                 0x4f0da4: (17155428, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordToggleButton', 152),
                 0x4f0da8: (17155440, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordTextView', 148),
                 0x4f0dac: (17155424, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.privacyControl', 144),
                 0x4f0db0: (17155420, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.serverWelcomeButton', 136),
                 0x4f0db4: (17155404, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpButton', 128),
                 0x4f0db8: (17155412, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpTextView', 124),
                 0x4f0dbc: (17155368, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.OKButton', 120),
                 0x4f0dc0: (17155400, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.titleTextView', 28),
        },
        classes={
                 0x4f0d7c: (15252540, 'OBJC_CLASS_$_MultiplayerWorldOptionsUI'),
        },
        instructions=[(5179948, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5180868, 'ldrhteq pc, [r6], r0')],
        calls=[(5180248, 'blx r5'), (5180284, 'blx r3'), (5180320, 'blx r3'), (5180356, 'blx r3'), (5180392, 'blx r3'), (5180428, 'blx r3'), (5180464, 'blx r3'), (5180500, 'blx r3'), (5180536, 'blx r3'), (5180572, 'blx r3'), (5180608, 'blx r3'), (5180644, 'blx r3'), (5180664, 'blx r2'), (5180700, 'blx r3'), (5180736, 'blx r3'), (5180776, 'blx r2')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[dealloc] @0x004f0a2c (231 words, 0 branches, 16 calls; read) - straight-line ARC/Apportable destructor, the batch\'s clearest ownership census. Head 0x004f0a38-0x004f0b14 builds the PIC base 0x0105faf4 (cell 0x004f0dc4 = 0xb6f0b0 + add-pc 0x004f0a3c), objc_msgSendSuper2 (GOT 0x0105b79c via cell 0x004f0d74), objc_msgSend (GOT 0x0105b7a0 via cell 0x004f0d80), SEL release (0x004f0d84 -> 0x00e7d5f0), SEL dismissAlertViews (0x004f0d90 -> 0x00e7d5dc), SEL dealloc (0x004f0d78 -> 0x00e7d5f4), the class ref cell 0x004f0d7c -> 0x00e8bc3c and 17 ivar offset cells, then at 0x004f0a40 \'sub r3,fp,#0x28\' starts the objc_super struct that the last call uses. Send 1 at 0x004f0b58: [self->titleTextView@28 release]; sends 2-12 at 0x004f0b7c..0x004f0ce4: one -release per widget ivar in the order OKButton@120, pvpTextView@124, pvpButton@128, serverWelcomeButton@136, privacyControl@144, passwordTextView@148, passwordToggleButton@152, passwordSetButton@156, addCreditButton@140, ownerPortalButton@160, customRulesButton@164; send 13 at 0x004f0cf8: [self dismissAlertViews]; send 14 at 0x004f0d1c: [self->addCreditUI@12 release]; send 15 at 0x004f0d40: [self->customGameRulesUI@180 release]; send 16 at 0x004f0d68 = objc_msgSendSuper2(&super, @selector(dealloc)) with super.receiver = self ([fp,-0x28]) and super.super_class = the class object ([fp,-0x24]). The alert ivars (textEntryAlertView@168, alertView@176) are deliberately NOT released here - dismissAlertViews does it. Not mentioned at all: world@4, optionsUI@8, backgroundShader@20, backgroundTexture@24, blackBackgroundShader@32, windowInfo@112 and cache@116.'),
    ),
    dict(
        name='mwou_11',
        method='MultiplayerWorldOptionsUI -[dismissAddCreditUI]',
        types='v8@0:4',
        start=5196356,
        end=5196544,
        disasm='disasm_worldtileloader_mwou_11.txt',
        base_add=5196372,
        base_literal=5196540,
        boundary='ARM.exidx end 0x004f4b00 (listing bound); next ObjC IMP 0x004f4b00 MultiplayerWorldOptionsUI -[isPauseMenu]',
        selectors={
                 0x4f4af4: (15193732, 'pauseResumeButtonTapped'),
        },
        imports={
                 0x4f4af0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f4ae8: (17155476, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.shouldDismissPauseUIOnExit', 172),
                 0x4f4aec: (17155468, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUINeedsDismissed', 16),
                 0x4f4af8: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={},
        instructions=[(5196356, 'push {fp, lr}'), (5196540, 'umlalseq fp, r6, r8, r0')],
        calls=[(5196508, 'blx r2')],
        branches=[(5196444, 'beq', 5196512)],
        semantics=('MultiplayerWorldOptionsUI -[dismissAddCreditUI] @0x004f4a44 (47 words, 1 branch, 1 call; read) - flag write plus a conditional notify, the counterpart of -[addCreditButton:]. Frame push {fp,lr}/mov fp,sp/sub sp,#0x10; base 0x0105faf4 from cell 0x004f4afc (0xb6b098 + add-pc 0x004f4a54). (A) \'movw ip,#1; strb ip,[self+16]\' at 0x004f4a60-0x004f4a80 sets self->addCreditUINeedsDismissed (offset cell 0x004f4aec -> GOT 0x0105c58c). (B) then \'ldrsb r0,[self+172]; cmp r0,#0; beq 0x004f4ae0\' reads back shouldDismissPauseUIOnExit (offset cell 0x004f4ae8 -> GOT 0x0105c594), and only when it is non-zero does it send objc_msgSend(self->world@4, @selector(pauseResumeButtonTapped)) (selref 0x004f4af4 -> 0x00e7d684, objc_msgSend GOT 0x0105b7a0 via cell 0x004f4af0). The flag is written before the test, so the pending dismiss is recorded even when the pause-UI notification is skipped.'),
    ),
    dict(
        name='mwou_12',
        method='MultiplayerWorldOptionsUI -[dismissAlertViews]',
        types='v8@0:4',
        start=5179340,
        end=5179948,
        disasm='disasm_worldtileloader_mwou_12.txt',
        base_add=5179356,
        base_literal=5179944,
        boundary='ARM.exidx end 0x004f0a2c (listing bound); next ObjC IMP 0x004f0a2c MultiplayerWorldOptionsUI -[dealloc]',
        selectors={
                 0x4f0a08: (15193576, 'autorelease'),
                 0x4f0a0c: (15193580, 'dismissWithClickedButtonIndex:animated:'),
                 0x4f0a14: (15193572, 'setDelegate:'),
                 0x4f0a18: (15193568, 'textFieldAtIndex:'),
                 0x4f0a1c: (15193564, 'dismissAlertViews'),
        },
        imports={
                 0x4f0a04: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f0a00: (17155456, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.alertView', 176),
                 0x4f0a10: (17155460, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.textEntryAlertView', 168),
                 0x4f0a20: (17155432, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customGameRulesUI', 180),
                 0x4f0a24: (17155464, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI', 12),
        },
        classes={},
        instructions=[(5179340, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5179944, 'adcseq pc, r6, r0, lsl r3')],
        calls=[(5179572, 'blx lr'), (5179608, 'blx r3'), (5179648, 'blx r3'), (5179668, 'blx r3'), (5179708, 'blx r3'), (5179744, 'blx r3'), (5179828, 'blx r5'), (5179864, 'blx r3')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[dismissAlertViews] @0x004f07cc (152 words, 0 branches, 8 calls; read) - teardown of every alert this panel can own, in three groups. Head 0x004f07d8-0x004f0868 pre-loads base 0x0105faf4 (cell 0x004f0a28 = 0xb6f310 + add-pc 0x004f07dc), the msgSend pointer, SEL autorelease (0x004f0a08 -> 0x00e7d5e8), SEL dismissWithClickedButtonIndex:animated: (0x004f0a0c -> 0x00e7d5ec), SEL setDelegate: (0x004f0a14 -> 0x00e7d5e4), SEL textFieldAtIndex: (0x004f0a18 -> 0x00e7d5e0), SEL dismissAlertViews (0x004f0a1c -> 0x00e7d5dc) and the constants 0xffffffff (mvn r6,#0) and 0 (movw r7,#0). Calls 1-2 (0x004f08b4, 0x004f08d8): the same dismissAlertViews message forwarded to the two child overlays self->addCreditUI@12 and self->customGameRulesUI@180. Calls 3-6 (0x004f0900..0x004f0960): the text-entry alert is disbanded - [[self->textEntryAlertView textFieldAtIndex:0] setDelegate:nil], [self->textEntryAlertView setDelegate:nil], [self->textEntryAlertView autorelease], then \'str 0,[self+168]\' clears textEntryAlertView@168. Calls 7-8 (0x004f09b4, 0x004f09d8): [self->alertView@176 dismissWithClickedButtonIndex:-1 animated:NO] (buttonIndex taken from the mvn r6,#0 constant, animated from the movw r7,#0 constant) followed by [self->alertView autorelease] and the same \'str 0\' clearing alertView@176. The -1 button index is the \'dismiss without invoking a button\' sentinel.'),
    ),
    dict(
        name='mwou_13',
        method='MultiplayerWorldOptionsUI -[dismissCustomRules]',
        types='v8@0:4',
        start=5198784,
        end=5198980,
        disasm='disasm_worldtileloader_mwou_13.txt',
        base_add=5198800,
        base_literal=5198976,
        boundary='ARM.exidx end 0x004f5484 (listing bound); next ObjC IMP 0x004f5484 MultiplayerWorldOptionsUI -[IAPForWorldTopupSucceeeded:transactionID:]',
        selectors={
                 0x4f5478: (15193648, 'dismissMultiplayerWorldOptions'),
        },
        imports={
                 0x4f5474: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f546c: (17155436, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customRulesOnlyMode', 18),
                 0x4f5470: (17155472, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.needsToDismissCustomRules', 17),
                 0x4f547c: (17155380, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.optionsUI', 8),
        },
        classes={},
        instructions=[(5198784, 'push {fp, lr}'), (5198976, 'adcseq sl, r6, ip, lsl r7')],
        calls=[(5198908, 'blx r2')],
        branches=[(5198844, 'beq', 5198916), (5198912, 'b', 5198948)],
        semantics=('MultiplayerWorldOptionsUI -[dismissCustomRules] @0x004f53c0 (49 words, 2 branches, 1 call; read) - ivar-flag gate, no super call. PIC base 0x0105faf4 (pool cell 0x004f5480 = 0xb6a71c + pc at 0x004f53d4). Byte-tests customRulesOnlyMode@18 (offset cell 0x004f546c -> slot 0x0105c56c -> 18); zero -> `beq 0x004f5444` and latches 1 into needsToDismissCustomRules@17 (cell 0x004f5470 -> slot 0x0105c590, `movw r0,#1; strb`); non-zero -> `[self->_optionsUI@8 dismissMultiplayerWorldOptions]` (ivar cell 0x004f547c -> slot 0x0105c534; selref cell 0x004f5478 -> 0x00e7d630) through objc_msgSend read from .got 0x0105b7a0 (cell 0x004f5474 = 0xffffbcac), `blx r2` at 0x004f543c, reply unused. So a dismiss requested while the UI is in custom-rules-only mode is forwarded to the options UI immediately, otherwise it is only deferred in the flag (render: is the body that consumes that flag).'),
    ),
    dict(
        name='mwou_14',
        method='MultiplayerWorldOptionsUI -[displayPasswordEntry]',
        types='v8@0:4',
        start=5193740,
        end=5194752,
        disasm='disasm_worldtileloader_mwou_14.txt',
        base_add=5193756,
        base_literal=5194748,
        boundary='ARM.exidx end 0x004f4400 (listing bound); next ObjC IMP 0x004f4400 MultiplayerWorldOptionsUI -[passwordToggleButton:]',
        selectors={
                 0x4f43b4: (15193708, 'show'),
                 0x4f43b8: (15193704, 'setText:'),
                 0x4f43bc: (15193536, 'serverPassword'),
                 0x4f43c4: (15193572, 'setDelegate:'),
                 0x4f43c8: (15193700, 'setReturnKeyType:'),
                 0x4f43cc: (15193696, 'setKeyboardType:'),
                 0x4f43d0: (15193692, 'setEnablesReturnKeyAutomatically:'),
                 0x4f43d4: (15193688, 'setAutocorrectionType:'),
                 0x4f43d8: (15193568, 'textFieldAtIndex:'),
                 0x4f43dc: (15193684, 'setAlertViewStyle:'),
                 0x4f43ec: (15193680, 'initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:'),
                 0x4f43f0: (15193436, 'alloc'),
        },
        imports={
                 0x4f43b0: (17151904, 'objc_msgSend'),
                 0x4f43e0: (16224456, '__CFConstantStringClassReference'),
                 0x4f43e4: (16224472, '__CFConstantStringClassReference'),
                 0x4f43e8: (16224488, '__CFConstantStringClassReference'),
                 0x4f43f8: (16224440, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x4f43ac: (17155460, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.textEntryAlertView', 168),
                 0x4f43c0: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={
                 0x4f43f4: (15245088, 'OBJC_CLASS_$_UIAlertView'),
        },
        instructions=[(5193740, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5194748, 'ldrsbteq fp, [r6], r0')],
        calls=[(5194232, 'blx r2'), (5194300, 'blx r6'), (5194356, 'blx r3'), (5194396, 'blx r3'), (5194424, 'blx r3'), (5194452, 'blx r3'), (5194476, 'blx r3'), (5194500, 'blx r3'), (5194536, 'blx r3'), (5194588, 'blx ip'), (5194620, 'blx r3'), (5194656, 'blx r3')],
        branches=[(5193804, 'bne', 5194660)],
        semantics=('MultiplayerWorldOptionsUI -[displayPasswordEntry] @0x004f400c (253 words, 1 branch, 12 calls; read) - builds and shows the password-entry UIAlertView. Guard: if self->_textEntryAlertView@168 != nil (offset cell 0x004f43ac -> slot 0x0105c584) -> `bne 0x004f43a4` epilogue, i.e. only one entry sheet at a time. Send 1 `[UIAlertView alloc]` (classref cell 0x004f43f4 -> 0x00e90cd8, selref \'alloc\' 0x004f43f0 -> 0x00e7d55c; `blx r2` 0x004f41f8); the alloc result is stored straight into self->_textEntryAlertView@168. Send 2 `initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:` (selref 0x004f43ec; `blx r6` 0x004f423c) with title = CFSTR \'Enter a password\' (cell 0x004f43e0 -> __cfstring 0x00f790c8), message = CFSTR \'Please set a new password. Share this password with people you wish to allow to connect to this world. As the owner, you can always connect without needing to enter the password, and can change or remove it at any time.\' (cell 0x004f43f8 -> 0x00f790b8), delegate = self (stack arg 0), cancelButtonTitle = \'Cancel\' (0x004f43e4 -> 0x00f790d8), otherButtonTitles = \'Done\', nil (0x004f43e8 -> 0x00f790e8). Then 9 configuration sends on the alert/its text field: `setAlertViewStyle:2` (UIAlertViewStylePlainTextInput, r2 = 2 from the `movw r1,#2` spill), `textFieldAtIndex:0` (result kept), `setAutocorrectionType:1`, `setEnablesReturnKeyAutomatically:YES` (sxtb of the 1 constant), `setKeyboardType:1`, `setReturnKeyType:9`, `setDelegate:self`, `setText:[self->_world@4 serverPassword]` (world cell 0x004f43c0 -> slot 0x0105c524; selref 0x004f43bc -> 0x00e7d5c0; prefills the field with the current password) and finally `[alert show]` (selref 0x004f43b4 -> 0x00e7d66c; `blx r2/r3` sites 0x004f4274..0x004f43a0). All 12 sends are register-indirect through the cached objc_msgSend GOT 0x0105b7a0 (cell 0x004f43b0).'),
    ),
    dict(
        name='mwou_15',
        method='MultiplayerWorldOptionsUI -[endTouch:]',
        types='v16@0:4{CGPoint=ff}8',
        start=5190064,
        end=5191020,
        disasm='disasm_worldtileloader_mwou_15.txt',
        base_add=5190080,
        base_literal=5191016,
        boundary='ARM.exidx end 0x004f356c (listing bound); next ObjC IMP 0x004f356c MultiplayerWorldOptionsUI -[OKButton:]',
        selectors={
                 0x4f353c: (15193644, 'endTouch:'),
        },
        imports={},
        ivars={
                 0x4f3528: (17155464, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI', 12),
                 0x4f352c: (17155432, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customGameRulesUI', 180),
                 0x4f3530: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
                 0x4f3538: (17155368, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.OKButton', 120),
                 0x4f3540: (17155404, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpButton', 128),
                 0x4f3544: (17155416, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditButton', 140),
                 0x4f3548: (17155420, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.serverWelcomeButton', 136),
                 0x4f354c: (17155424, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.privacyControl', 144),
                 0x4f3550: (17155428, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordToggleButton', 152),
                 0x4f3554: (17155444, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordSetButton', 156),
                 0x4f3558: (17155448, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.ownerPortalButton', 160),
                 0x4f355c: (17155452, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customRulesButton', 164),
        },
        classes={},
        instructions=[(5190064, 'push {r4, sl, fp, lr}'), (5191016, 'adcseq ip, r6, ip, lsr 18')],
        calls=[(5190200, 'bl loc.imp.objc_msgSend'), (5190308, 'bl loc.imp.objc_msgSend'), (5190460, 'bl loc.imp.objc_msgSend'), (5190520, 'bl loc.imp.objc_msgSend'), (5190580, 'bl loc.imp.objc_msgSend'), (5190640, 'bl loc.imp.objc_msgSend'), (5190700, 'bl loc.imp.objc_msgSend'), (5190760, 'bl loc.imp.objc_msgSend'), (5190820, 'bl loc.imp.objc_msgSend'), (5190880, 'bl loc.imp.objc_msgSend'), (5190940, 'bl loc.imp.objc_msgSend')],
        branches=[(5190136, 'beq', 5190208), (5190204, 'b', 5190944), (5190244, 'beq', 5190316), (5190312, 'b', 5190944)],
        semantics=('MultiplayerWorldOptionsUI -[endTouch:] @0x004f31b0 (239 words, 4 branches, 11 calls; read) - touch release router, byte-identical twin of moveTouch: except for its selector. types v16@0:4{CGPoint=ff}8 (point in r2/r3). (a) If self->_addCreditUI@12 != nil (offset cell 0x004f3528 -> slot 0x0105c588) -> forward `[self->_addCreditUI endTouch:<p>]` (selref cell 0x004f353c -> 0x00e7d62c; `bl loc.imp.objc_msgSend` 0x004f3238) and jump to the epilogue (`b 0x004f3520`); (b) else if self->_customGameRulesUI@180 != nil (cell 0x004f352c) -> forward `[self->_customGameRulesUI endTouch:<p>]` (`bl` 0x004f32a4) and return; (c) else dispatch to the nine option controls in address order with a single window-local point conversion up front (`vldr/vsub.f32` of windowInfo@112 (cell 0x004f3530) [+8]/[+0xc]): OKButton@120 (0x004f333c), pvpButton@128 (0x004f3378), addCreditButton@140 (0x004f33b4), serverWelcomeButton@136 (0x004f33f0), privacyControl@144 (0x004f342c), passwordToggleButton@152 (0x004f3468), passwordSetButton@156 (0x004f34a4), ownerPortalButton@160 (0x004f34e0), customRulesButton@164 (0x004f351c) - all `endTouch:` through the one selref cell, all PLT sends (no register-cached msgSend in this body). Branch skeleton identical to mwou_20 (only pool words and the selector differ).'),
    ),
    dict(
        name='mwou_16',
        method='MultiplayerWorldOptionsUI -[iapCancelled]',
        types='v8@0:4',
        start=5199632,
        end=5199732,
        disasm='disasm_worldtileloader_mwou_16.txt',
        base_add=5199648,
        base_literal=5199728,
        boundary='ARM.exidx end 0x004f5774 (listing bound); next ObjC IMP 0x004f5774 MultiplayerWorldOptionsUI -[.cxx_construct]',
        selectors={
                 0x4f5768: (15193784, 'iapCancelled'),
        },
        imports={
                 0x4f5764: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f576c: (17155464, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI', 12),
        },
        classes={},
        instructions=[(5199632, 'push {fp, lr}'), (5199728, 'adcseq sl, r6, ip, asr 7')],
        calls=[(5199704, 'blx r3')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[iapCancelled] @0x004f5710 (25 words, 0 branches, 1 call; read) - single-send store callback: `[self->_addCreditUI@12 iapCancelled]`. Apportable offset-cell frame (push {fp,lr}; mov fp,sp; sub sp,#8) with PIC base 0x0105faf4 from pool cell 0x004f5770 (0xb6a3cc + pc); objc_msgSend out of .got 0x0105b7a0 (cell 0x004f5764 = 0xffffbcac), selref \'iapCancelled\' at 0x00e7d6b8 (cell 0x004f5768 = 0xffe1dbc4), addCreditUI offset cell 0x004f576c -> slot 0x0105c588 -> 12. The only call is `blx r3` at 0x004f5758; the reply is discarded (void) and a nil addCreditUI makes the send a no-op.'),
    ),
    dict(
        name='mwou_17',
        method='MultiplayerWorldOptionsUI -[iapStarted]',
        types='v8@0:4',
        start=5199332,
        end=5199432,
        disasm='disasm_worldtileloader_mwou_17.txt',
        base_add=5199348,
        base_literal=5199428,
        boundary='ARM.exidx end 0x004f5774; body trimmed at the next IMP 0x004f5648 MultiplayerWorldOptionsUI -[cloudInterface]',
        selectors={
                 0x4f563c: (15193772, 'startCloudTopup'),
        },
        imports={
                 0x4f5638: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f5640: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={},
        instructions=[(5199332, 'push {fp, lr}'), (5199428, 'ldrshteq sl, [r6], r8')],
        calls=[(5199404, 'blx r3')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[iapStarted] @0x004f55e4 (25 words, 0 branches, 1 call; read; roster-trimmed) - single-send store callback: `[self->_world@4 startCloudTopup]`. Same 25-word stub shape as iapCancelled: PIC base 0x0105faf4 (pool cell 0x004f5644 = 0xb6a4f8), objc_msgSend from .got 0x0105b7a0 (cell 0x004f5638 = 0xffffbcac), selref \'startCloudTopup\' at 0x00e7d6ac (cell 0x004f563c = 0xffe1dbb8), ivar cell 0x004f5640 -> slot 0x0105c524 -> world@4; one call, `blx r3` at 0x004f562c, reply unused.'),
    ),
    dict(
        name='mwou_18',
        method='MultiplayerWorldOptionsUI -[initWithWorld:windowInfo:cache:optionsUI:]',
        types='@24@0:4@8^{WindowInfo=ffffffff}12@16@20',
        start=5167796,
        end=5178844,
        disasm='disasm_worldtileloader_mwou_18.txt',
        base_add=5167820,
        base_literal=5167984,
        boundary='ARM.exidx end 0x004f05dc (listing bound); next ObjC IMP 0x004f07cc MultiplayerWorldOptionsUI -[dismissAlertViews]',
        selectors={
                 0x4edb78: (15193420, 'init'),
                 0x4edb88: (15193468, 'server'),
                 0x4edb90: (15193464, 'setTarget:action:'),
                 0x4edb94: (15193460, 'OKButton:'),
                 0x4edb9c: (15193456, 'setBackgroundSelectedTexture:'),
                 0x4edba4: (15193432, 'textureNamed:'),
                 0x4edbac: (15193452, 'setBackgroundTexture:'),
                 0x4edbc4: (15193424, 'arrayWithObjects:'),
                 0x4edbd8: (15193428, 'shaderNamed:attributes:uniforms:'),
                 0x4edc00: (15193436, 'alloc'),
                 0x4edc08: (15193440, 'standardFont'),
                 0x4edc0c: (15193444, 'initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:'),
                 0x4edc1c: (15193448, 'initWithFrame:cache:windowInfo:title:'),
                 0x4edc28: (15193472, 'client'),
                 0x4ef47c: (15193476, 'isAdmin'),
                 0x4ef480: (15193480, 'isCloudGame'),
                 0x4ef484: (15193496, 'pvpButton:'),
                 0x4ef48c: (15193492, 'setOn:'),
                 0x4ef494: (15193488, 'pvpEnabled'),
                 0x4ef4a8: (15193484, 'initWithFrame:cache:windowInfo:'),
                 0x4ef4ac: (15193504, 'canAddWorldCredit'),
                 0x4ef4b0: (15193500, 'addCreditButton:'),
                 0x4efc94: (15193508, 'setEnabled:'),
                 0x4efca4: (15193464, 'setTarget:action:'),
                 0x4efca8: (15193512, 'serverWelcomeButton:'),
                 0x4efcb0: (15193456, 'setBackgroundSelectedTexture:'),
                 0x4efcb4: (15193432, 'textureNamed:'),
                 0x4efcbc: (15193452, 'setBackgroundTexture:'),
                 0x4efcc8: (15193436, 'alloc'),
                 0x4efcd0: (15193448, 'initWithFrame:cache:windowInfo:title:'),
                 0x4f0068: (15193516, 'isOwner'),
                 0x4f006c: (15193528, 'serverPrivacySetting'),
                 0x4f0070: (15193524, 'privacyControl:'),
                 0x4f0084: (15193424, 'arrayWithObjects:'),
                 0x4f0098: (15193520, 'initWithFrame:cache:windowInfo:titles:'),
                 0x4f0394: (15193536, 'serverPassword'),
                 0x4f051c: (15193532, 'selectItemAtIndex:'),
                 0x4f052c: (15193464, 'setTarget:action:'),
                 0x4f0530: (15193456, 'setBackgroundSelectedTexture:'),
                 0x4f0534: (15193432, 'textureNamed:'),
                 0x4f053c: (15193452, 'setBackgroundTexture:'),
                 0x4f0548: (15193436, 'alloc'),
                 0x4f0550: (15193440, 'standardFont'),
                 0x4f0554: (15193444, 'initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:'),
                 0x4f055c: (15193448, 'initWithFrame:cache:windowInfo:title:'),
                 0x4f0560: (15193548, 'customRules'),
                 0x4f0568: (15193560, 'initWithWorld:windowInfo:cache:parentUI:'),
                 0x4f0574: (15193476, 'isAdmin'),
                 0x4f0578: (15193492, 'setOn:'),
                 0x4f0580: (15193484, 'initWithFrame:cache:windowInfo:'),
                 0x4f058c: (15193508, 'setEnabled:'),
                 0x4f059c: (15193540, 'passwordToggleButton:'),
                 0x4f05a8: (15193544, 'passwordSetButton:'),
                 0x4f05bc: (15193552, 'ownerPortalButton:'),
                 0x4f05c8: (15193556, 'customRulesButton:'),
        },
        imports={
                 0x4edb74: (17151900, 'objc_msgSendSuper2'),
                 0x4edb80: (17151968, '__stack_chk_guard'),
                 0x4edb84: (17151904, 'objc_msgSend'),
                 0x4edba0: (16224168, '__CFConstantStringClassReference'),
                 0x4edbb0: (16224152, '__CFConstantStringClassReference'),
                 0x4edbc8: (16224008, '__CFConstantStringClassReference'),
                 0x4edbcc: (16224024, '__CFConstantStringClassReference'),
                 0x4edbd0: (16224040, '__CFConstantStringClassReference'),
                 0x4edbd4: (16224056, '__CFConstantStringClassReference'),
                 0x4edbdc: (16223992, '__CFConstantStringClassReference'),
                 0x4edbe4: (16224088, '__CFConstantStringClassReference'),
                 0x4edbe8: (16224072, '__CFConstantStringClassReference'),
                 0x4edbf0: (16224104, '__CFConstantStringClassReference'),
                 0x4edc10: (16224120, '__CFConstantStringClassReference'),
                 0x4edc20: (16224136, '__CFConstantStringClassReference'),
                 0x4ef49c: (16224184, '__CFConstantStringClassReference'),
                 0x4ef4b8: (16224232, '__CFConstantStringClassReference'),
                 0x4ef4bc: (16224216, '__CFConstantStringClassReference'),
                 0x4ef4c4: (16224200, '__CFConstantStringClassReference'),
                 0x4efc90: (17151904, 'objc_msgSend'),
                 0x4efc9c: (16224248, '__CFConstantStringClassReference'),
                 0x4efca0: (16224264, '__CFConstantStringClassReference'),
                 0x4f0078: (16224152, '__CFConstantStringClassReference'),
                 0x4f0088: (16224312, '__CFConstantStringClassReference'),
                 0x4f008c: (16224280, '__CFConstantStringClassReference'),
                 0x4f0090: (16224296, '__CFConstantStringClassReference'),
                 0x4f0520: (17151968, '__stack_chk_guard'),
                 0x4f0524: (17151904, 'objc_msgSend'),
                 0x4f0584: (16224232, '__CFConstantStringClassReference'),
                 0x4f0588: (16224216, '__CFConstantStringClassReference'),
                 0x4f0594: (16224328, '__CFConstantStringClassReference'),
                 0x4f05a0: (16224360, '__CFConstantStringClassReference'),
                 0x4f05ac: (16224344, '__CFConstantStringClassReference'),
                 0x4f05b8: (16224376, '__CFConstantStringClassReference'),
                 0x4f05d0: (16224392, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x4edb8c: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
                 0x4edb98: (17155368, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.OKButton', 120),
                 0x4edba8: (17155372, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.cache', 116),
                 0x4edbb4: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
                 0x4edbbc: (17155380, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.optionsUI', 8),
                 0x4edbe0: (17155384, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.backgroundShader', 20),
                 0x4edbec: (17155388, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.blackBackgroundShader', 32),
                 0x4edbf4: (17155392, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.backgroundTexture', 24),
                 0x4edbf8: (17155396, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.orthoMatrix', 48),
                 0x4edc14: (17155400, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.titleTextView', 28),
                 0x4ef488: (17155404, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpButton', 128),
                 0x4ef490: (17155408, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpDisabled', 132),
                 0x4ef4a0: (17155412, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpTextView', 124),
                 0x4ef4b4: (17155416, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditButton', 140),
                 0x4efc98: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
                 0x4efcac: (17155420, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.serverWelcomeButton', 136),
                 0x4efcb8: (17155372, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.cache', 116),
                 0x4efccc: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
                 0x4f0074: (17155424, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.privacyControl', 144),
                 0x4f0398: (17155428, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordToggleButton', 152),
                 0x4f0528: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
                 0x4f0538: (17155372, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.cache', 116),
                 0x4f0540: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
                 0x4f0564: (17155432, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customGameRulesUI', 180),
                 0x4f0570: (17155436, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customRulesOnlyMode', 18),
                 0x4f0590: (17155428, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordToggleButton', 152),
                 0x4f0598: (17155440, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordTextView', 148),
                 0x4f05a4: (17155444, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordSetButton', 156),
                 0x4f05c0: (17155448, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.ownerPortalButton', 160),
                 0x4f05cc: (17155452, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customRulesButton', 164),
        },
        classes={
                 0x4edb7c: (15252540, 'OBJC_CLASS_$_MultiplayerWorldOptionsUI'),
                 0x4edbc0: (15245060, 'OBJC_CLASS_$_NSArray'),
                 0x4edbfc: (15245064, 'OBJC_CLASS_$_MJTextView'),
                 0x4edc04: (15245068, 'OBJC_CLASS_$_BitmapFont'),
                 0x4edc18: (15245072, 'OBJC_CLASS_$_MJButton'),
                 0x4ef4a4: (15245076, 'OBJC_CLASS_$_MJToggleButton'),
                 0x4efcc0: (15245072, 'OBJC_CLASS_$_MJButton'),
                 0x4f007c: (15245060, 'OBJC_CLASS_$_NSArray'),
                 0x4f0094: (15245080, 'OBJC_CLASS_$_MJSegmentedControl'),
                 0x4f0544: (15245064, 'OBJC_CLASS_$_MJTextView'),
                 0x4f054c: (15245068, 'OBJC_CLASS_$_BitmapFont'),
                 0x4f0558: (15245072, 'OBJC_CLASS_$_MJButton'),
                 0x4f056c: (15245084, 'OBJC_CLASS_$_CustomGameRulesUI'),
                 0x4f057c: (15245076, 'OBJC_CLASS_$_MJToggleButton'),
        },
        instructions=[(5167796, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5178840, 'adcseq pc, r6, r8, lsr 19')],
        calls=[(5167940, 'blx r7'), (5168704, 'bl loc.imp.objc_msgSend'), (5168776, 'bl loc.imp.objc_msgSend'), (5168824, 'bl loc.imp.objc_msgSend'), (5168900, 'bl loc.imp.objc_msgSend'), (5168960, 'bl loc.imp.objc_msgSend'), (5169000, 'bl loc.imp.objc_msgSend'), (5169060, 'bl loc.imp.objc_msgSend'), (5169172, 'bl 0x4f05dc'), (5169368, 'bl 0x4f0734'), (5169396, 'bl loc.imp.objc_msgSend'), (5169500, 'bl loc.imp.objc_msgSend'), (5169540, 'bl 0x4f0780'), (5169668, 'bl loc.imp.objc_msgSend'), (5169740, 'bl 0x4f0734'), (5169764, 'bl loc.imp.objc_msgSend'), (5169904, 'bl loc.imp.objc_msgSend'), (5169992, 'blx lr'), (5170024, 'blx r3'), (5170092, 'blx lr'), (5170124, 'blx r3'), (5170172, 'blx lr'), (5170208, 'blx r3'), (5170296, 'blx r3'), (5170372, 'blx r2'), (5170468, 'blx r2'), (5170724, 'bl 0x4f0734'), (5170764, 'bl loc.imp.objc_msgSend'), (5170884, 'bl loc.imp.objc_msgSend'), (5170928, 'bl 0x4f0780'), (5171056, 'bl loc.imp.objc_msgSend'), (5171128, 'bl 0x4f0734'), (5171152, 'bl loc.imp.objc_msgSend'), (5171272, 'bl loc.imp.objc_msgSend'), (5171328, 'blx ip'), (5171448, 'blx r3'), (5171496, 'blx lr'), (5171560, 'blx r2'), (5171620, 'bl 0x4f0734'), (5171684, 'blx r2'), (5171748, 'bl 0x4f0734'), (5172012, 'bl loc.imp.objc_msgSend'), (5172160, 'bl loc.imp.objc_msgSend'), (5172248, 'blx lr'), (5172280, 'blx r3'), (5172348, 'blx lr'), (5172380, 'blx r3'), (5172428, 'blx lr'), (5172464, 'blx r3'), (5172560, 'blx ip'), (5172616, 'bl 0x4f0734'), (5172692, 'blx r2'), (5172920, 'bl loc.imp.objc_msgSend'), (5173056, 'bl loc.imp.objc_msgSend'), (5173144, 'blx lr'), (5173176, 'blx r3'), (5173244, 'blx lr'), (5173276, 'blx r3'), (5173324, 'blx lr'), (5173372, 'bl 0x4f0734'), (5173436, 'blx r2'), (5173512, 'blx r2'), (5173804, 'bl 0x4f0734'), (5173888, 'bl loc.imp.objc_msgSend'), (5173916, 'bl loc.imp.objc_msgSend'), (5174052, 'bl loc.imp.objc_msgSend'), (5174140, 'blx lr'), (5174172, 'blx r3'), (5174240, 'blx lr'), (5174272, 'blx r3'), (5174320, 'blx lr'), (5174356, 'blx r3'), (5174624, 'bl loc.imp.objc_msgSend'), (5174668, 'bl 0x4f0734'), (5174696, 'bl loc.imp.objc_msgSend'), (5174816, 'bl loc.imp.objc_msgSend'), (5174856, 'bl 0x4f0780'), (5174984, 'bl loc.imp.objc_msgSend'), (5175056, 'bl 0x4f0734'), (5175080, 'bl loc.imp.objc_msgSend'), (5175200, 'bl loc.imp.objc_msgSend'), (5175256, 'blx ip'), (5175416, 'blx r5'), (5175464, 'blx lr'), (5175560, 'blx ip'), (5175816, 'bl 0x4f0734'), (5175852, 'bl loc.imp.objc_msgSend'), (5176000, 'bl loc.imp.objc_msgSend'), (5176088, 'blx lr'), (5176120, 'blx r3'), (5176188, 'blx lr'), (5176220, 'blx r3'), (5176268, 'blx lr'), (5176312, 'blx ip'), (5176364, 'bl 0x4f0734'), (5176456, 'bl loc.imp.objc_msgSend_stret'), (5176564, 'bl sym.imp.memset'), (5176880, 'bl loc.imp.objc_msgSend'), (5177016, 'bl loc.imp.objc_msgSend'), (5177104, 'blx lr'), (5177136, 'blx r3'), (5177204, 'blx lr'), (5177236, 'blx r3'), (5177284, 'blx lr'), (5177348, 'blx r2'), (5177440, 'bl loc.imp.objc_msgSend_stret'), (5177536, 'bl sym.imp.memset'), (5177752, 'bl loc.imp.objc_msgSend'), (5177900, 'bl loc.imp.objc_msgSend'), (5177988, 'blx lr'), (5178020, 'blx r3'), (5178088, 'blx lr'), (5178120, 'blx r3'), (5178168, 'blx lr'), (5178252, 'bl loc.imp.objc_msgSend_stret'), (5178300, 'bl sym.imp.memset'), (5178460, 'blx r2'), (5178560, 'blx lr'), (5178644, 'bl sym.imp.__stack_chk_fail')],
        branches=[(5167968, 'bne', 5168172), (5167980, 'b', 5178596), (5170220, 'bne', 5170312), (5170308, 'beq', 5178176), (5170384, 'beq', 5171500), (5170480, 'beq', 5170516), (5170484, 'b', 5170496), (5171572, 'beq', 5172568), (5171696, 'bne', 5171784), (5172476, 'bne', 5172564), (5172564, 'b', 5172568), (5172704, 'beq', 5172724), (5173448, 'beq', 5177288), (5173524, 'beq', 5177288), (5174380, 'bne', 5174476), (5174392, 'b', 5174500), (5174484, 'bne', 5174496), (5174496, 'b', 5174500), (5175276, 'beq', 5175300), (5175476, 'bne', 5175564), (5176436, 'beq', 5176532), (5176460, 'b', 5176568), (5176580, 'beq', 5176620), (5177360, 'beq', 5178172), (5177420, 'beq', 5177504), (5177444, 'b', 5177540), (5177552, 'beq', 5178172), (5178172, 'b', 5178588), (5178232, 'beq', 5178268), (5178256, 'b', 5178304), (5178316, 'beq', 5178584), (5178584, 'b', 5178588), (5178628, 'bne', 5178644)],
        semantics=('MultiplayerWorldOptionsUI -[initWithWorld:windowInfo:cache:optionsUI:] @0x004edab4 (2762 words, 33 branches, 119 calls; [census]) - the entire multiplayer world-options panel is built here: PvP/shader assets, an ortho matrix, 12 widgets and 3 conditionally-created child objects. FRAME/PRELUDE 0x4edab4-0x4edb44: push {r4,r5,r6,r7,r8,sl,fp,lr} / add fp,sp,#0x18 / sub sp,sp,#0x770 / bic sp,sp,#0xf; PIC base 0x0105faf4 from the body\'s own base cell 0x004edb70 (0xb72020 + add-pc at 0x004edacc - the same cell is re-materialised 14 times across the body and is the only \'unclassified\' pool cell). Base is copied to [sp,0x440], the float/rect scratch buffer is sp+0x480 ([sp,0x444]), the objc_super sits at sp+0x680, self is kept at [sp,0x6a0] and the return value at [sp,0x6a4]. 0x4edaf8-0x4edb44 loads __stack_chk_guard (GOT 0x0105b7e0 via cell 0x004edb80) into [sp,0x44c] and performs the only super call, objc_msgSendSuper2(&super, @selector(init)) through GOT 0x0105b79c, with super.receiver = self and super.super_class = the class object from cell 0x004edb7c (0x00e8bc3c). 0x4edb4c-0x4edb60 compares the result with 0: non-nil falls into 0x4edc2c, nil stores 0 into [sp,0x6a4] and jumps to 0x4f04e4. The shared epilogue 0x4f04e4-0x4f0514 re-reads __stack_chk_guard, compares it with [sp,0x44c] and either returns [sp,0x38] or calls __stack_chk_fail - this is the only body in the batch that carries a stack canary. CALL TABLE (119 calls): 36 bl loc.imp.objc_msgSend, 24 blx lr, 19 blx r3, 13 bl 0x4f0734, 9 blx r2, 5 blx ip, 3 bl 0x4f0780, 3 bl loc.imp.objc_msgSend_stret, 3 bl sym.imp.memset, and one each of blx r7 (the super call), blx r5, bl 0x4f05dc and bl sym.imp.__stack_chk_fail. Local helpers resolved by disassembling them: 0x4f05dc = GLKMatrix4MakeOrtho(left,right,bottom,top,near,far) (called once at 0x4ee014, filling the 64-byte destination sp+0x640 which is then copied into orthoMatrix@48); 0x4f0734 (13 calls) and 0x4f0780 (3 calls) are two byte-identical 4-float rect packers that store r1,r2,r3,[sp] into [r0..r0+0xc] - the 0x4f0780 copy always feeds initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:, i.e. the three MJTextView builds, while the 0x4f0734 copy feeds the MJButton/MJSegmentedControl frames. SELECTORS (36 distinct selref references; counts): alloc 10, setTarget:action: 9, textureNamed: 8, setBackgroundSelectedTexture: 7, setBackgroundTexture: 7, initWithFrame:cache:windowInfo:title: 6, isAdmin 4, isCloudGame 3, standardFont 3, initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color: 3, setEnabled: 3, customRules 3, arrayWithObjects: 2, setOn: 2, initWithFrame:cache:windowInfo: 2, and 1 each for init, server, client, OKButton:, shaderNamed:attributes:uniforms:, pvpButton:, pvpEnabled, canAddWorldCredit, addCreditButton:, serverWelcomeButton:, isOwner, serverPrivacySetting, privacyControl:, initWithFrame:cache:windowInfo:titles:, serverPassword, selectItemAtIndex:, passwordToggleButton:, passwordSetButton:, ownerPortalButton:, customRulesButton:, initWithWorld:windowInfo:cache:parentUI:. The panel\'s whole data model is the World object: [world server], [world client], [world isAdmin] x4, [world isCloudGame] x3, [world isOwner], [world pvpEnabled], [world canAddWorldCredit], [world serverPrivacySetting], [world serverPassword] and [world customRules] x3 (a 64-byte struct returned through objc_msgSend_stret). BRANCH SKELETON (33 branches; in-body targets 0x4edc2c 0x4ee488 0x4ee540 0x4ee554 0x4ee92c 0x4eea48 0x4eed54 0x4eed58 0x4eedf4 0x4ef4cc 0x4ef4e0 0x4ef4e4 0x4ef804 0x4ef90c 0x4efcd4 0x4efcf8 0x4efd2c 0x4effc8 0x4f00a0 0x4f00c4 0x4f033c 0x4f0340 0x4f039c 0x4f03c0 0x4f04d8 0x4f04dc 0x4f04e4 0x4f0514): (1) 0x4edb60 bne - the super-init nil test; (2) 0x4ee42c / 0x4ee484 - the head guard, [world server] is compared with the zero constant saved at [sp,0x438] (written with r0 = 0 at 0x4edc7c) and only when it is nil is [world client] fetched and compared with 0; when server and client are both nil the whole widget body is skipped and control jumps straight to the trailing customRules block 0x4f0340; (3) 0x4ee4d0 - if (![world isAdmin]) goto 0x4ee92c; (4) 0x4ee530 / 0x4ee534 - if (![world isCloudGame]) goto 0x4ee554 else 0x4ee540, where 0x4ee540 materialises mvn r0,#0x4f (-80) plus the pool float at 0x4ee53c into the scratch buffer (a position/colour constant); (5) 0x4ee974 - a second isCloudGame test that can skip ahead to 0x4eed58; (6) 0x4ee9f0 - the isAdmin test guarding the add-credit block at 0x4eea48; (7) 0x4eecfc / 0x4eed54 - the canAddWorldCredit result choosing between [self->addCreditButton setEnabled:NO] (0x4eed04-0x4eed50) and skipping; (8) 0x4eede0 - the isAdmin-driven choice of the welcome-message button title; (9) 0x4ef0c8 and 0x4ef114 - two consecutive guards that both jump to 0x4effc8, so the privacy control and the whole password row exist only when the world is a cloud game AND the caller is its owner; (10) 0x4ef46c / 0x4ef4d4 / 0x4ef4e0 - the 3-way mapping of [world serverPrivacySetting] onto the segmented-control index (2 -> 1, 3 -> 2, anything else 0); (11) 0x4ef7ec and 0x4ef8b4 - the password-row on/enabled decisions; (12) three identical customRules sequences (0x4efc74/0x4efc8c, 0x4f0010/0x4f004c/0x4f0064 and 0x4f0378/0x4f0390/0x4f03cc) that each fetch the 64-byte struct by hidden pointer, memset it to zero when the stret call returned nil, and then read the signed byte at struct offset 40 to decide \'WEB PORTAL\' vs \'OWNER PORTAL\' (0x4efd04), whether to build the EDIT RULES button (0x4f00d0) and whether to create the customGameRulesUI at all (0x4f03cc); (13) 0x4f0504 - the stack-canary check. LITERALS (26 unique CFString structs, each reached as <cell value>+base): PAUSED - WORLD OPTIONS 0x00f78f78, OK 0x00f78f88, pauseBackground.png 0x00f78f68, InventoryButtonBackgroundGreen.png 0x00f78f98, InventoryButtonBackgroundSelectedGreen.png 0x00f78fa8, InventoryButtonBackground.png 0x00f78fd8, InventoryButtonBackgroundSelected.png 0x00f78fe8, PVP: 0x00f78fb8, ADD CREDIT... 0x00f78fc8, VIEW WELCOME MESSAGE 0x00f78ff8, VIEW/EDIT WELCOME MESSAGE 0x00f79008, PRIVATE 0x00f79038, PUBLIC 0x00f79018, SEARCH 0x00f79028, PASSWORD: 0x00f79048, SET... 0x00f79058, OWNER PORTAL 0x00f79068, WEB PORTAL 0x00f79078, EDIT RULES 0x00f79088, plus the seven shader strings StandardObject 0x00f78ef8, position 0x00f78f08, texCoord 0x00f78f18, mvp_matrix 0x00f78f28, texture 0x00f78f38, ColoredNoTexture 0x00f78f48 and color 0x00f78f58. Numeric constants seen: 0x41000000 (8.0f) and 0x4210xxxx / 0x4220xxxx / 0x42e4xxxx float pairs handed to the rect packers, mvn r0,#0x4f (-80) for the PvP placement, and movw r8,#1 for customRulesOnlyMode. BLOCK WALK. A 0x4edc2c-0x4ee2f4 assets and text: self->backgroundShader@20 = [Shader shaderNamed:@"StandardObject" attributes:@[position,texCoord,mvp_matrix,texture] uniforms:...] (NSArray arrayWithObjects: at 0x4eddb4), self->blackBackgroundShader@32 = the same call with \'ColoredNoTexture\' and a \'color\' attribute array, self->backgroundTexture@24 = [cache textureNamed:@"pauseBackground.png"], GLKMatrix4MakeOrtho into orthoMatrix@48, then titleTextView@28 = [[MJTextView alloc] initWithFrame:... cache:self->cache@116 windowInfo:self->windowInfo@112 string:@"PAUSED - WORLD OPTIONS" horizontalAlignment:... font:[BitmapFont standardFont] color:...] and OKButton@120 = [[MJButton alloc] initWithFrame:... cache:... windowInfo:... title:@"OK"] wired with setTarget:self action:@selector(OKButton:), setBackgroundSelectedTexture:[cache textureNamed:@"InventoryButtonBackgroundSelectedGreen.png"] and setBackgroundTexture:[cache textureNamed:@"...Green.png"]. B 0x4ee2f4-0x4ee42c the head guard of item (2). C 0x4ee430-0x4ee554 the world role tests and the PvP constant. D 0x4ee554-0x4ee928 pvpTextView@124 and pvpButton@128 (an MJToggleButton built with initWithFrame:cache:windowInfo:), then setOn:[world pvpEnabled] and setTarget:self action:@selector(pvpButton:). E 0x4ee92c-0x4ee9f4 a second isCloudGame test. F 0x4ee9f4-0x4eed54 addCreditButton@140 = [[MJButton alloc] initWithFrame:... title:@"ADD CREDIT..."] with setTarget:action:@selector(addCreditButton:), the standard green textures, and the isAdmin / canAddWorldCredit pair that greys it out. G 0x4eed58-0x4effc8 serverWelcomeButton@136 titled \'VIEW WELCOME MESSAGE\', or \'VIEW/EDIT WELCOME MESSAGE\' when isAdmin; then, only for an owned cloud world, privacyControl@144 = [[MJSegmentedControl alloc] initWithFrame:... cache:... windowInfo:... titles:@[PRIVATE,PUBLIC,SEARCH]] with setTarget:action:@selector(privacyControl:) and an initial selectItemAtIndex: derived from serverPrivacySetting, plus passwordTextView@148 (\'PASSWORD:\'), passwordToggleButton@152 (a MJToggleButton) and passwordSetButton@156 (\'SET...\'); finally ownerPortalButton@160, whose title switches between \'WEB PORTAL\' and \'OWNER PORTAL\' on the customRules byte at offset 40. H 0x4effc8-0x4f033c admins only: customRulesButton@164 titled \'EDIT RULES\', gated by the same struct byte. I 0x4f0340-0x4f04d8 the no-server/no-client path: a third customRules fetch and, when its byte is set, self->customRulesOnlyMode@18 = YES (\'movw r8,#1; strb r8,[self+18]\' at 0x4f0430) immediately before [[CustomGameRulesUI alloc] initWithWorld:self->world@4 windowInfo:self->windowInfo@112 cache:self->cache@116 parentUI:self] is stored into customGameRulesUI@180 (class from cell 0x004f056c -> 0x00e89f1c). J 0x4f04dc writes self back into [sp,0x6a4] and falls into the canary epilogue. 144 of the 2762 listing words are literal-pool data interleaved with the code (they disassemble as \'invalid\' or as stray adcseq/umlalseq rows and carry no control flow).'),
    ),
    dict(
        name='mwou_19',
        method='MultiplayerWorldOptionsUI -[isPauseMenu]',
        types='c8@0:4',
        start=5196544,
        end=5196572,
        disasm='disasm_worldtileloader_mwou_19.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004f4b1c (listing bound); next ObjC IMP 0x004f4b1c MultiplayerWorldOptionsUI -[selectAddCreditOption:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5196544, 'sub sp, sp, 8'), (5196568, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[isPauseMenu] @0x004f4b00 (7 words, 0 branches, 0 calls; read) - constant YES: `movw r2,#1; sxtb r0,r2`. No PIC base, no pool cells, no ivar access and no message sends at all (just the self/_cmd spill); this overlay always declares itself a pause menu (the render: body leaves early on it).'),
    ),
    dict(
        name='mwou_20',
        method='MultiplayerWorldOptionsUI -[moveTouch:]',
        types='v16@0:4{CGPoint=ff}8',
        start=5189108,
        end=5190064,
        disasm='disasm_worldtileloader_mwou_20.txt',
        base_add=5189124,
        base_literal=5190060,
        boundary='ARM.exidx end 0x004f31b0 (listing bound); next ObjC IMP 0x004f31b0 MultiplayerWorldOptionsUI -[endTouch:]',
        selectors={
                 0x4f3180: (15193640, 'moveTouch:'),
        },
        imports={},
        ivars={
                 0x4f316c: (17155464, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI', 12),
                 0x4f3170: (17155432, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customGameRulesUI', 180),
                 0x4f3174: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
                 0x4f317c: (17155368, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.OKButton', 120),
                 0x4f3184: (17155404, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpButton', 128),
                 0x4f3188: (17155416, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditButton', 140),
                 0x4f318c: (17155420, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.serverWelcomeButton', 136),
                 0x4f3190: (17155424, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.privacyControl', 144),
                 0x4f3194: (17155428, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordToggleButton', 152),
                 0x4f3198: (17155444, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordSetButton', 156),
                 0x4f319c: (17155448, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.ownerPortalButton', 160),
                 0x4f31a0: (17155452, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customRulesButton', 164),
        },
        classes={},
        instructions=[(5189108, 'push {r4, sl, fp, lr}'), (5190060, 'adcseq ip, r6, r8, ror 25')],
        calls=[(5189244, 'bl loc.imp.objc_msgSend'), (5189352, 'bl loc.imp.objc_msgSend'), (5189504, 'bl loc.imp.objc_msgSend'), (5189564, 'bl loc.imp.objc_msgSend'), (5189624, 'bl loc.imp.objc_msgSend'), (5189684, 'bl loc.imp.objc_msgSend'), (5189744, 'bl loc.imp.objc_msgSend'), (5189804, 'bl loc.imp.objc_msgSend'), (5189864, 'bl loc.imp.objc_msgSend'), (5189924, 'bl loc.imp.objc_msgSend'), (5189984, 'bl loc.imp.objc_msgSend')],
        branches=[(5189180, 'beq', 5189252), (5189248, 'b', 5189988), (5189288, 'beq', 5189360), (5189356, 'b', 5189988)],
        semantics=('MultiplayerWorldOptionsUI -[moveTouch:] @0x004f2df4 (239 words, 4 branches, 11 calls; read) - drag router, the twin of endTouch: (`moveTouch:` instead of `endTouch:`; every other instruction byte-identical). (a) self->_addCreditUI@12 != nil -> `[self->_addCreditUI moveTouch:<p>]` (selref cell 0x004f3180 -> 0x00e7d628; `bl` 0x004f2e7c) then epilogue; (b) else self->_customGameRulesUI@180 != nil -> `[self->_customGameRulesUI moveTouch:<p>]` (`bl` 0x004f2ee8) then epilogue; (c) else convert the point once (windowInfo@112 [+8]/[+0xc], cells 0x004f316c/0x004f3170/0x004f3174) and dispatch `moveTouch:` to OKButton@120, pvpButton@128, addCreditButton@140, serverWelcomeButton@136, privacyControl@144, passwordToggleButton@152, passwordSetButton@156, ownerPortalButton@160, customRulesButton@164 (`bl` sites 0x004f2f80..0x004f3160). 11 PLT objc_msgSend calls, no indirect/GOT send form.'),
    ),
    dict(
        name='mwou_21',
        method='MultiplayerWorldOptionsUI -[ownerPortalButton:]',
        types='v12@0:4@8',
        start=5196904,
        end=5197828,
        disasm='disasm_worldtileloader_mwou_21.txt',
        base_add=5196920,
        base_literal=5197824,
        boundary='ARM.exidx end 0x004f5004 (listing bound); next ObjC IMP 0x004f5264 MultiplayerWorldOptionsUI -[customRulesButton:]',
        selectors={
                 0x4f4fb4: (15193708, 'show'),
                 0x4f4fbc: (15193756, 'addButtonWithTitle:block:'),
                 0x4f4fc0: (17111040, 'ELF'),
                 0x4f4fd4: (15193748, 'setCancelButtonWithTitle:block:'),
                 0x4f4fd8: (17111008, 'ELF'),
                 0x4f4fe4: (15193744, 'initWithTitle:message:'),
                 0x4f4fe8: (15193740, 'uppercaseString'),
                 0x4f4fec: (15193436, 'alloc'),
                 0x4f4ff8: (15193736, 'stringWithFormat:'),
        },
        imports={
                 0x4f4fb0: (17151904, 'objc_msgSend'),
                 0x4f4fb8: (16224536, '__CFConstantStringClassReference'),
                 0x4f4fcc: (17151928, '_NSConcreteStackBlock'),
                 0x4f4fd0: (16224520, '__CFConstantStringClassReference'),
                 0x4f4fe0: (16224360, '__CFConstantStringClassReference'),
                 0x4f4ff4: (16224504, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x4f4fac: (17155456, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.alertView', 176),
        },
        classes={
                 0x4f4ff0: (15245100, 'OBJC_CLASS_$_BlockAlertView'),
                 0x4f4ffc: (15245096, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(5196904, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5197824, 'adcseq sl, r6, r4, ror lr')],
        calls=[(5197380, 'blx r3'), (5197416, 'blx r3'), (5197448, 'blx r3'), (5197484, 'blx ip'), (5197596, 'blx r5'), (5197692, 'blx r5'), (5197728, 'blx r3')],
        branches=[(5196972, 'bne', 5197732)],
        semantics=('MultiplayerWorldOptionsUI -[ownerPortalButton:] @0x004f4c68 (231 words, 1 branch, 7 calls; read) - builds, wires and shows the \'OWNER PORTAL\' BlockAlertView. Re-entry guard first: if self->_alertView@176 != nil (offset cell 0x004f4fac -> slot 0x0105c580) -> `bne 0x004f4fa4` (epilogue) - no second sheet. Then: message = [[NSString stringWithFormat: CFSTR \'The owner portal is a web site where you can monitor worlds, manage settings, and even chat in worlds you own. All from outside the game!\' (cell 0x004f4ff4 -> 0x00f790f8)] uppercaseString] (classref cell 0x004f4ffc = OBJC_CLASS_$_NSString, selrefs 0x004f4ff8 \'stringWithFormat:\' and 0x004f4fe8 \'uppercaseString\'; the format call passes no substitution arguments); alert = [[BlockAlertView alloc] initWithTitle:CFSTR \'OWNER PORTAL\' (cell 0x004f4fe0 -> 0x00f79068) message:<uppercased text>] (classref cell 0x004f4ff0 -> 0x00e90cd8, selrefs 0x004f4fec \'alloc\' / 0x004f4fe4 \'initWithTitle:message:\'), stored into self->_alertView@176 with a plain `str`; then two 6-word stack blocks are built in place (isa = _NSConcreteStackBlock GOT 0x0105b7b8 via cell 0x004f4fcc, flags word 0xc2000000 from pool cell 0x004f4fc8, captured self at +0x14) and passed to `setCancelButtonWithTitle:CFSTR \'CANCEL\' (0x004f4fd0 -> 0x00f79108) block:` (selref 0x004f4fd4; block1 invoke 0x004f5004, descriptor 0x010517e0) and `addButtonWithTitle:CFSTR \'VISIT PORTAL\' (0x004f4fb8 -> 0x00f79118) block:` (selref 0x004f4fbc; block2 invoke 0x004f5108, descriptor 0x01051800), and finally `[self->_alertView show]` (selref 0x004f4fb4 -> 0x00e7d66c). All 7 calls are register-indirect (blx); the two block bodies are detached .text functions outside the batch roster.'),
    ),
    dict(
        name='mwou_22',
        method='MultiplayerWorldOptionsUI -[passwordSetButton:]',
        types='v12@0:4@8',
        start=5195496,
        end=5195576,
        disasm='disasm_worldtileloader_mwou_22.txt',
        base_add=5195512,
        base_literal=5195572,
        boundary='ARM.exidx end 0x004f4738 (listing bound); next ObjC IMP 0x004f4738 MultiplayerWorldOptionsUI -[addCreditButton:]',
        selectors={
                 0x4f4730: (15193712, 'displayPasswordEntry'),
        },
        imports={
                 0x4f472c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(5195496, 'push {fp, lr}'), (5195572, 'ldrshteq fp, [r6], r4')],
        calls=[(5195552, 'blx ip')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[passwordSetButton:] @0x004f46e8 (20 words, 0 branches, 1 call; read) - button action forwarded to itself: `[self displayPasswordEntry]`. Receiver is self (`ldr r0,[fp,-4]`), selref cell 0x004f4730 -> 0x00e7d670 \'displayPasswordEntry\', objc_msgSend from .got 0x0105b7a0 (cell 0x004f472c = 0xffffbcac), PIC base 0x0105faf4 (cell 0x004f4734). The sender argument (r2) is spilled to [sp,4] and never read; single `blx ip` at 0x004f4720; no ivar cell at all.'),
    ),
    dict(
        name='mwou_23',
        method='MultiplayerWorldOptionsUI -[passwordToggleButton:]',
        types='v12@0:4@8',
        start=5194752,
        end=5195496,
        disasm='disasm_worldtileloader_mwou_23.txt',
        base_add=5194768,
        base_literal=5195492,
        boundary='ARM.exidx end 0x004f46e8 (listing bound); next ObjC IMP 0x004f46e8 MultiplayerWorldOptionsUI -[passwordSetButton:]',
        selectors={
                 0x4f46b0: (15193536, 'serverPassword'),
                 0x4f46b8: (15193712, 'displayPasswordEntry'),
                 0x4f46bc: (15193676, 'sendNewPasswordToServer:'),
                 0x4f46c0: (15193508, 'setEnabled:'),
                 0x4f46c8: (15193456, 'setBackgroundSelectedTexture:'),
                 0x4f46d0: (15193432, 'textureNamed:'),
                 0x4f46dc: (15193452, 'setBackgroundTexture:'),
        },
        imports={
                 0x4f46ac: (17151904, 'objc_msgSend'),
                 0x4f46cc: (16224424, '__CFConstantStringClassReference'),
                 0x4f46e0: (16224408, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x4f46b4: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
                 0x4f46c4: (17155444, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordSetButton', 156),
                 0x4f46d4: (17155372, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.cache', 116),
                 0x4f46d8: (17155428, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordToggleButton', 152),
        },
        classes={},
        instructions=[(5194752, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5195492, 'ldrsbteq fp, [r6], ip')],
        calls=[(5194840, 'blx lr'), (5195160, 'blx r3'), (5195192, 'blx r3'), (5195260, 'blx lr'), (5195292, 'blx r3'), (5195336, 'blx ip'), (5195376, 'blx r3'), (5195424, 'blx r2')],
        branches=[(5194876, 'beq', 5195384), (5195380, 'b', 5195428)],
        semantics=('MultiplayerWorldOptionsUI -[passwordToggleButton:] @0x004f4400 (186 words, 2 branches, 8 calls; read) - the password on/off toggle. Head: `[self->_world@4 serverPassword]` (world cell 0x004f46b4 -> slot 0x0105c524; selref 0x004f46b0 -> 0x00e7d5c0; `blx lr` 0x004f4458) -> result compared with 0 (`movw ip,#0`) and normalised to the BOOL hasPassword = (password != nil) at [fp,-0x25]. If hasPassword == 0 -> `beq 0x4f4678` -> `[self displayPasswordEntry]` (selref cell 0x004f46b8 -> 0x00e7d670; `blx r2` 0x004f46a0): i.e. no password yet, so ask for one (mwou_14). If hasPassword != 0 -> the toggle is switching the password OFF: `[self->_cache@116 textureNamed:CFSTR \'toggleButtonOff.png\']` (cache cell 0x004f46d4 -> slot 0x0105c52c, selref 0x004f46d0 -> 0x00e7d558, texture CFSTR cell 0x004f46e0 -> 0x00f79098) -> `[self->_passwordToggleButton@152 setBackgroundTexture:<tex>]` (toggle cell 0x004f46d8 -> slot 0x0105c564, selref 0x004f46dc -> 0x00e7d56c); `[cache textureNamed:CFSTR \'toggleButtonOffSelected.png\']` (cell 0x004f46cc -> 0x00f790a8) -> `[passwordToggleButton setBackgroundSelectedTexture:<tex>]` (selref 0x004f46c8 -> 0x00e7d570); `[self->_passwordSetButton@156 setEnabled:NO]` (button cell 0x004f46c4 -> slot 0x0105c574, selref 0x004f46c0 -> 0x00e7d5a4, r2 = the `movw r4,#0` zero); and `[self->_world sendNewPasswordToServer:0]` (selref 0x004f46bc -> 0x00e7d64c, r2 = the zero spilled at 0x004f44a4-stage) - i.e. it clears the world password server-side. 8 blx sends, one GOT msgSend, no super call; the state textures are the \'Off\' pair, matching the flipped toggle.'),
    ),
    dict(
        name='mwou_24',
        method='MultiplayerWorldOptionsUI -[privacyControl:]',
        types='v12@0:4@8',
        start=5191552,
        end=5192536,
        disasm='disasm_worldtileloader_mwou_24.txt',
        base_add=5191568,
        base_literal=5192532,
        boundary='ARM.exidx end 0x004f3b58 (listing bound); next ObjC IMP 0x004f3b58 MultiplayerWorldOptionsUI -[textField:shouldChangeCharactersInRange:replacementString:]',
        selectors={
                 0x4f3b18: (15193664, 'sendNewPrivacySettingToServer:'),
                 0x4f3b20: (15193660, 'selectedIndex'),
                 0x4f3b28: (15193508, 'setEnabled:'),
                 0x4f3b34: (15193492, 'setOn:'),
                 0x4f3b38: (15193536, 'serverPassword'),
                 0x4f3b3c: (15193456, 'setBackgroundSelectedTexture:'),
                 0x4f3b44: (15193432, 'textureNamed:'),
                 0x4f3b4c: (15193452, 'setBackgroundTexture:'),
        },
        imports={
                 0x4f3b14: (17151904, 'objc_msgSend'),
                 0x4f3b40: (16224424, '__CFConstantStringClassReference'),
                 0x4f3b50: (16224408, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x4f3b1c: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
                 0x4f3b24: (17155424, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.privacyControl', 144),
                 0x4f3b2c: (17155444, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordSetButton', 156),
                 0x4f3b30: (17155428, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordToggleButton', 152),
                 0x4f3b48: (17155372, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.cache', 116),
        },
        classes={},
        instructions=[(5191552, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5192532, 'adcseq ip, r6, ip, asr r3')],
        calls=[(5191664, 'blx ip'), (5191712, 'blx ip'), (5191916, 'blx r3'), (5191960, 'blx ip'), (5192028, 'blx lr'), (5192060, 'blx r3'), (5192128, 'blx lr'), (5192160, 'blx r3'), (5192300, 'blx r7'), (5192368, 'blx r3'), (5192412, 'blx ip'), (5192456, 'blx ip')],
        branches=[(5191724, 'bne', 5192168), (5192164, 'b', 5192460)],
        semantics=('MultiplayerWorldOptionsUI -[privacyControl:] @0x004f3780 (246 words, 2 branches, 12 calls; read) - the privacy segmented control\'s action. Reads index = `[self->_privacyControl@144 selectedIndex]` (control cell 0x004f3b24 -> slot 0x0105c560; selref 0x004f3b20 -> 0x00e7d63c; `blx ip` 0x004f37f0), computes privacy = index+1 (`add r0,r0,#1`) and sends `[self->_world@4 sendNewPrivacySettingToServer:privacy]` (world cell 0x004f3b1c -> slot 0x0105c524; selref 0x004f3b18 -> 0x00e7d640; `blx ip` 0x004f3820). Then `cmp privacy,1; bne 0x4f39e8`: (a) privacy == 1 (segment 0, password off) -> texture pair again from _cache@116 (`textureNamed:CFSTR \'toggleButtonOff.png\'` / `\'toggleButtonOffSelected.png\'`, cells 0x004f3b40/0x004f3b50 -> 0x00f790a8/0x00f79098) applied to passwordToggleButton@152 (`setBackgroundTexture:` / `setBackgroundSelectedTexture:`, cells 0x004f3b30/0x004f3b4c), `[passwordToggleButton setEnabled:NO]` (`blx r3` 0x004f38ec) and `[self->_passwordSetButton@156 setEnabled:NO]` (`blx ip` 0x004f3918) - both password controls disabled; (b) privacy != 1 (password required) -> queries `[self->_world serverPassword]` (`blx r7` 0x004f3a6c), derives hasPassword = (password != nil) into [fp,-0x29], then `[passwordToggleButton setOn:hasPassword]` (selref 0x004f3b34 -> 0x00e7d594; `blx r3` 0x004f3ab0), `[passwordSetButton setEnabled:YES]` (sxtb of the `movw lr,#1` constant; `blx ip` 0x004f3adc) and `[passwordToggleButton setEnabled:hasPassword]` (`blx ip` 0x004f3b08). 12 register-indirect sends, no super call.'),
    ),
    dict(
        name='mwou_25',
        method='MultiplayerWorldOptionsUI -[pvpButton:]',
        types='v12@0:4@8',
        start=5191124,
        end=5191448,
        disasm='disasm_worldtileloader_mwou_25.txt',
        base_add=5191140,
        base_literal=5191444,
        boundary='ARM.exidx end 0x004f3718 (listing bound); next ObjC IMP 0x004f3718 MultiplayerWorldOptionsUI -[serverWelcomeButton:]',
        selectors={
                 0x4f3704: (15193492, 'setOn:'),
                 0x4f370c: (15193652, 'sendSetPVPEnabledToServer:'),
        },
        imports={
                 0x4f3700: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f36fc: (17155408, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpDisabled', 132),
                 0x4f3708: (17155404, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpButton', 128),
                 0x4f3710: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={},
        instructions=[(5191124, 'push {r4, r5, r6, r7, fp, lr}'), (5191444, 'adcseq ip, r6, r8, lsl 10')],
        calls=[(5191320, 'blx lr'), (5191384, 'blx ip')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[pvpButton:] @0x004f35d4 (81 words, 0 branches, 2 calls; read) - PvP toggle handler. Reads pvpDisabled@132 (cell 0x004f36fc -> slot 0x0105c550, `ldrsb`), flips it (`eor 1; and 1`) into the local v = !pvpDisabled_old, then (1) sends `[self->_world@4 sendSetPVPEnabledToServer:!v]` (world cell 0x004f3710 -> slot 0x0105c524; selref 0x004f370c -> 0x00e7d634; `blx lr` at 0x004f3698) and (2) sends `[self->_pvpButton@128 setOn:!v]` (cell 0x004f3708 -> slot 0x0105c54c; selref 0x004f3704 -> 0x00e7d594; `blx ip` at 0x004f36d8), and finally writes the flipped value back: `strb v,[self+132]`. The compiler evaluated !pvpDisabled twice, so both message arguments equal the pre-flip value negated, i.e. the new \'PvP enabled\' state (!pvpDisabled); the toggle button is kept in sync with the world flag.'),
    ),
    dict(
        name='mwou_26',
        method='MultiplayerWorldOptionsUI -[render:]',
        types='v12@0:4f8',
        start=5181308,
        end=5187708,
        disasm='disasm_worldtileloader_mwou_26.txt',
        base_add=5181328,
        base_literal=5181956,
        boundary='ARM.exidx end 0x004f287c (listing bound); next ObjC IMP 0x004f287c MultiplayerWorldOptionsUI -[touchIsInViewAtAll:]',
        selectors={
                 0x4f1214: (15193584, 'release'),
                 0x4f1218: (15193596, 'render:'),
                 0x4f122c: (15193600, 'program'),
                 0x4f1230: (15193604, 'uniformLocations'),
                 0x4f1234: (15193608, 'objectAtIndex:'),
                 0x4f1238: (15193612, 'intValue'),
                 0x4f124c: (15193616, 'name'),
                 0x4f1250: (15193620, 'maxS'),
                 0x4f1254: (15193624, 'maxT'),
                 0x4f125c: (15193628, 'renderFrame:projectionMatrix:'),
        },
        imports={
                 0x4f1210: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f1208: (17155464, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI', 12),
                 0x4f120c: (17155468, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUINeedsDismissed', 16),
                 0x4f121c: (17155432, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customGameRulesUI', 180),
                 0x4f1220: (17155472, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.needsToDismissCustomRules', 17),
                 0x4f1224: (17155388, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.blackBackgroundShader', 32),
                 0x4f123c: (17155396, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.orthoMatrix', 48),
                 0x4f1240: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
                 0x4f1244: (17155384, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.backgroundShader', 20),
                 0x4f1248: (17155392, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.backgroundTexture', 24),
                 0x4f1258: (17155400, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.titleTextView', 28),
                 0x4f1260: (17155368, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.OKButton', 120),
                 0x4f2854: (17155412, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpTextView', 124),
                 0x4f2858: (17155404, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpButton', 128),
                 0x4f285c: (17155416, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditButton', 140),
                 0x4f2860: (17155420, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.serverWelcomeButton', 136),
                 0x4f2864: (17155424, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.privacyControl', 144),
                 0x4f2868: (17155440, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordTextView', 148),
                 0x4f286c: (17155428, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordToggleButton', 152),
                 0x4f2870: (17155444, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordSetButton', 156),
                 0x4f2874: (17155448, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.ownerPortalButton', 160),
                 0x4f2878: (17155452, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customRulesButton', 164),
        },
        classes={},
        instructions=[(5181308, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5187704, 'invalid')],
        calls=[(5181516, 'blx lr'), (5181644, 'blx r3'), (5181820, 'blx lr'), (5181948, 'blx r3'), (5182076, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5182088, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5182096, 'bl sym.imp.__wrap_glEnable'), (5182152, 'bl loc.imp.objc_msgSend'), (5182156, 'bl sym.imp.__wrap_glUseProgram'), (5182192, 'bl loc.imp.objc_msgSend'), (5182220, 'bl loc.imp.objc_msgSend'), (5182244, 'bl loc.imp.objc_msgSend'), (5182288, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5182320, 'bl loc.imp.objc_msgSend'), (5182340, 'bl loc.imp.objc_msgSend'), (5182356, 'bl loc.imp.objc_msgSend'), (5182400, 'bl sym.imp.__wrap_glUniform4f'), (5182456, 'bl sym.drawShaderQuadNoTexture'), (5182500, 'bl loc.imp.objc_msgSend'), (5182504, 'bl sym.imp.__wrap_glUseProgram'), (5182536, 'bl loc.imp.objc_msgSend'), (5182556, 'bl loc.imp.objc_msgSend'), (5182572, 'bl loc.imp.objc_msgSend'), (5182580, 'bl sym.imp.__wrap_glUniform1i'), (5182624, 'bl loc.imp.objc_msgSend'), (5182644, 'bl sym.imp.__wrap_glBindTexture'), (5182676, 'bl loc.imp.objc_msgSend'), (5182696, 'bl loc.imp.objc_msgSend'), (5182712, 'bl loc.imp.objc_msgSend'), (5182740, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5182772, 'bl loc.imp.objc_msgSend'), (5182816, 'bl loc.imp.objc_msgSend'), (5182880, 'bl sym.drawShaderQuad'), (5183280, 'bl loc.imp.objc_msgSend'), (5183676, 'bl loc.imp.objc_msgSend'), (5184072, 'bl loc.imp.objc_msgSend'), (5184468, 'bl loc.imp.objc_msgSend'), (5184864, 'bl loc.imp.objc_msgSend'), (5185260, 'bl loc.imp.objc_msgSend'), (5185656, 'bl loc.imp.objc_msgSend'), (5186052, 'bl loc.imp.objc_msgSend'), (5186448, 'bl loc.imp.objc_msgSend'), (5186844, 'bl loc.imp.objc_msgSend'), (5187240, 'bl loc.imp.objc_msgSend'), (5187632, 'bl loc.imp.objc_msgSend'), (5187640, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5187648, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5187656, 'bl sym.imp.__wrap_glDisable')],
        branches=[(5181388, 'beq', 5181656), (5181424, 'beq', 5181572), (5181568, 'b', 5181652), (5181648, 'b', 5187660), (5181652, 'b', 5181656), (5181692, 'beq', 5182056), (5181728, 'beq', 5181876), (5181872, 'b', 5182052), (5181952, 'b', 5187660), (5182052, 'b', 5182056)],
        semantics=('MultiplayerWorldOptionsUI -[render:] @0x004f0f7c (1600 words, 10 branches, 48 calls; CENSUS) - the overlay\'s per-frame renderer, types v12@0:4f8 (one float argument, the layer depth). Frame: push {r4,r5,r6,r7,r8,sl,fp,lr}; add fp,sp,#0x18; sub sp,sp,#0x5a0; bic sp,sp,#0xf (16-byte aligned); the float argument is captured with `vmov s0,r2` into [sp+0x594] and PIC base 0x0105faf4 comes from pool cell 0x004f1204. Shape: 10 branch rows, all forward guards, in three groups - the modal early-outs (4), the shader/texture pass (0), and the 12-subview chain (0) - so the body is one long straight-line sequence plus two nested if/else heads; 1388 of the 1568 real instruction rows are ldr/str (849/539), the 44 PLT + 4 indirect calls are the only control transfer besides those branches.\nSEND TABLE (48 calls): (1) the child-modal head, 4 register sends - `[self->_addCreditUI@12 release]` (blx lr 0x004f104c) and `[self->_addCreditUI render:<layer>]` (blx r3 0x004f10cc), `[self->_customGameRulesUI@180 release]` (0x004f117c) and `[self->_customGameRulesUI render:<layer>]` (0x004f11fc), the heads being selrefs \'release\' (cell 0x004f1214 -> 0x00e7d5f0) and \'render:\' (cell 0x004f1218 -> 0x00e7d5fc). (2) 17 shader/texture sends through PLT objc_msgSend: for blackBackgroundShader@32 (cell 0x004f1224 -> slot 0x0105c53c) `program` (0x004f12c8; selref cell 0x004f122c -> 0x00e7d600) then `[[shader uniformLocations] objectAtIndex:0] intValue` (0x004f12f0/0x004f130c/0x004f1324; cells 0x004f1230/0x004f1234/0x004f1238) feeding glUniformMatrix4fv; `[... objectAtIndex:1] intValue` (0x004f1370/0x004f1384/0x004f1394) feeding glUniform4f; for backgroundShader@20 (cell 0x004f1244 -> slot 0x0105c538) `program` (0x004f1424) + `[... objectAtIndex:1] intValue` (0x004f1448/0x004f145c/0x004f146c) feeding glUniform1i; for backgroundTexture@24 (cell 0x004f1248 -> slot 0x0105c540) `name` (0x004f14a0; selref cell 0x004f124c -> 0x00e7d610) feeding glBindTexture, `[... objectAtIndex:0] intValue` (0x004f14d4/0x004f14e8/0x004f14f8) feeding the second glUniformMatrix4fv, and `maxS` / `maxT` (0x004f1534/0x004f1560; cells 0x004f1250/0x004f1254 -> 0x00e7d614/0x00e7d618) feeding drawShaderQuad. (3) 12 `renderFrame:projectionMatrix:` sends (selref cell 0x004f125c -> 0x00e7d61c) to the stack of subviews in address order: titleTextView@28 (0x004f1730, cell 0x004f1258), OKButton@120 (0x004f18bc, cell 0x004f1260), pvpTextView@124 (0x004f1a48, cell 0x004f2854), pvpButton@128 (0x004f1bd4, cell 0x004f2858), addCreditButton@140 (0x004f1d60, cell 0x004f285c), serverWelcomeButton@136 (0x004f1eec, cell 0x004f2860), privacyControl@144 (0x004f2078, cell 0x004f2864), passwordTextView@148 (0x004f2204, cell 0x004f2868), passwordToggleButton@152 (0x004f2390, cell 0x004f286c), passwordSetButton@156 (0x004f251c, cell 0x004f2870), ownerPortalButton@160 (0x004f26a8, cell 0x004f2874), customRulesButton@164 (0x004f2830, cell 0x004f2878); each passes the layer float in r2 and the 64-byte ortho matrix by value on the stack. (4) 15 GL wrapper calls - glEnableVertexAttribArray(0)/(1), glEnable, 2x glUseProgram, 2x glUniformMatrix4fv, glUniform4f, glUniform1i, glBindTexture, drawShaderQuadNoTexture, drawShaderQuad, at the tail 2x glDisableVertexAttribArray(1)/(0) and glDisable.\nBRANCH SKELETON (10, all forward): 0x4f0fcc beq->0x4f10d8 (addCreditUI == nil), 0x4f0ff0 beq->0x4f1084 (addCreditUINeedsDismissed@16 == 0), 0x4f1080 b->0x4f10d4, 0x4f10d0 b->0x4f284c (epilogue), 0x4f10d4 b->0x4f10d8, 0x4f10fc beq->0x4f1268 (customGameRulesUI@180 == nil), 0x4f1120 beq->0x4f11b4 (needsToDismissCustomRules@17 == 0), 0x4f11b0 b->0x4f1264, 0x4f1200 b->0x4f284c (epilogue), 0x4f1264 b->0x4f1268. So: a live addCreditUI (flag clear) or a live customGameRulesUI (flag clear) short-circuits the whole frame after its own `render:`; a flagged child is `release`d, its ivar zeroed and its flag cleared (`str 0` / `strb 0` at 0x4f1054-0x004f107c and 0x004f1188-0x004f11ac) and rendering of the overlay proceeds. This is the consumer of needsToDismissCustomRules@17 that mwou_13 latches.\nBLOCK WALK: (i) head 0x004f0f7c-0x004f1264 = the two modal guards above (4 sends, 9 branches). (ii) 0x004f1268-0x004f15a0 = the GL pass: glEnableVertexAttribArray(0), (1), glEnable(0xbe2 = GL_BLEND); blackBackgroundShader program -> glUseProgram; uniformLocations/[0].intValue -> glUniformMatrix4fv(loc,1,0,&self->_orthoMatrix@48) (orthoMatrix reached through its own offset cell, the 64 bytes read straight out of the ivar with the `ldr ip,[r0,ip]!` + [r0,4..0x3c] chain); uniformLocations/[1].intValue -> glUniform4f(loc, 0.043137256f, 0.086274512f, 0.235294119f, 0.670000017f) (bit patterns 0x3d30b0b1/0x3db0b0b1/0x3e70f0f1/0x3f2b851f, 0x4f13c0) and drawShaderQuadNoTexture(-wi[+8], +wi[+8], -wi[+0xc], +wi[+0xc]) (0x4f13f8; windowInfo@112 cell 0x004f1240 -> slot 0x0105c530, the two halves taken from wi+8/wi+0xc and negated with `eor 0x80000000`); then backgroundShader program -> glUseProgram, [1].intValue -> glUniform1i(loc, 0) (r1 = [sp,0x25c] = the 0 constant, 0x4f1474), backgroundTexture `name` -> glBindTexture(0xde1 = GL_TEXTURE_2D, name) (0x4f14b4), [0].intValue -> glUniformMatrix4fv(loc,1,0,&orthoMatrix) (0x4f1514), and maxS/maxT -> drawShaderQuad(x0=-132.0f, x1=132.0f, y0=-160.0f, y1=160.0f, then the stack floats 0.0f, maxS, maxT, 0.0f) (0x4f15a0; constants 0xc3040000/0x43040000/0xc3200000/0x43200000 materialised with movw/movt; helper 0x007c43dc reads r0/r1 as the x pair and r2/r3 as the y pair, per its own vertex emission). (iii) 0x004f15a4-0x004f2848 = the 12-subview chain: for every subview the body re-reads self->_orthoMatrix@48 word by word (the `ldr ip,[r0,ip]!` pre-indexed load plus `ldr rX,[r0,4..0x3c]`) and copies all 16 words twice through stack staging slots (0x510..0x54c -> 0x1d4..0x1f8 for OKButton, similarly 0x510-style windows per subview) into the outgoing argument area, then `ldr r0,[sp,<subview slot>]; mov r1,lr; bl loc.imp.objc_msgSend` - that 16-word, 32-instruction sequence repeated 12 times is what makes this body 1600 words with 1388 ldr/str. (iv) tail 0x004f2830-0x004f2850: last subview send, glDisableVertexAttribArray(1), glDisableVertexAttribArray(0), glDisable(0xbe2), then `sub sp,fp,#0x18; pop {r4,r5,r6,r7,r8,sl,fp,pc}` - no super call anywhere (no msgSendSuper2 import) and no early return from the middle of the chain.\nCONSTANTS/STRINGS: the only C strings are the two selector names resolved through selrefs (no CFString literal is referenced in this body); the numeric signature is GL_BLEND 0xbe2, GL_TEXTURE_2D 0xde1, glUniformMatrix4fv flag words 1 (transpose) and 0, glUniform1i value 0, the overlay colour (0.043137256, 0.086274512, 0.235294119, 0.670000017) and the 264x320-unit panel quad (-132/132/-160/160) drawn with the background texture\'s maxS/maxT; the layer float arrives from the caller and is forwarded unchanged to the two child UIs.'),
    ),
    dict(
        name='mwou_27',
        method='MultiplayerWorldOptionsUI -[selectAddCreditOption:]',
        types='v12@0:4c8',
        start=5196572,
        end=5196904,
        disasm='disasm_worldtileloader_mwou_27.txt',
        base_add=5196588,
        base_literal=5196900,
        boundary='ARM.exidx end 0x004f4c68 (listing bound); next ObjC IMP 0x004f4c68 MultiplayerWorldOptionsUI -[ownerPortalButton:]',
        selectors={
                 0x4f4c4c: (15193504, 'canAddWorldCredit'),
                 0x4f4c54: (15193508, 'setEnabled:'),
                 0x4f4c60: (15193500, 'addCreditButton:'),
        },
        imports={
                 0x4f4c48: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f4c50: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
                 0x4f4c58: (17155416, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditButton', 140),
                 0x4f4c5c: (17155476, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.shouldDismissPauseUIOnExit', 172),
        },
        classes={},
        instructions=[(5196572, 'push {r4, sl, fp, lr}'), (5196900, 'adcseq sl, r6, r0, asr 31')],
        calls=[(5196652, 'blx ip'), (5196748, 'blx ip'), (5196836, 'blx r3')],
        branches=[(5196664, 'bne', 5196756), (5196752, 'b', 5196864)],
        semantics=('MultiplayerWorldOptionsUI -[selectAddCreditOption:] @0x004f4b1c (83 words, 2 branches, 3 calls; read; types v12@0:4c8 - the BOOL is latched into shouldDismissPauseUIOnExit@172). Gate on `[self->_world@4 canAddWorldCredit]` (world cell 0x004f4c50 -> slot 0x0105c524; selref 0x004f4c4c -> 0x00e7d5a0; `blx ip` at 0x004f4b6c), result sxtb\'d and compared: (a) canAddWorldCredit == 0 -> `[self->_addCreditButton@140 setEnabled:NO]` (button cell 0x004f4c58 -> slot 0x0105c558; selref 0x004f4c54 -> 0x00e7d5a4; `blx ip` at 0x004f4bcc) then `b 0x004f4c40` epilogue; (b) canAddWorldCredit != 0 -> `bne 0x004f4bd4` and self-forwards `[self addCreditButton:self->_addCreditButton]` (selref 0x004f4c60 -> 0x00e7d59c; `blx r3` at 0x004f4c24), then stores the incoming BOOL into shouldDismissPauseUIOnExit@172 (cell 0x004f4c5c -> slot 0x0105c594, `strb`). objc_msgSend is re-read from .got 0x0105b7a0 (cells 0x004f4c48/0x004f4b80) on the PLT-free register path.'),
    ),
    dict(
        name='mwou_28',
        method='MultiplayerWorldOptionsUI -[serverWelcomeButton:]',
        types='v12@0:4@8',
        start=5191448,
        end=5191552,
        disasm='disasm_worldtileloader_mwou_28.txt',
        base_add=5191464,
        base_literal=5191548,
        boundary='ARM.exidx end 0x004f3780 (listing bound); next ObjC IMP 0x004f3780 MultiplayerWorldOptionsUI -[privacyControl:]',
        selectors={
                 0x4f3774: (15193656, 'viewOrEditWelcomeMessage'),
        },
        imports={
                 0x4f3770: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f3778: (17155364, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.world', 4),
        },
        classes={},
        instructions=[(5191448, 'push {r4, sl, fp, lr}'), (5191548, 'adcseq ip, r6, r4, asr 7')],
        calls=[(5191524, 'blx ip')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[serverWelcomeButton:] @0x004f3718 (26 words, 0 branches, 1 call; read) - button action: `[self->_world@4 viewOrEditWelcomeMessage]`. world offset cell 0x004f3778 -> slot 0x0105c524 -> 4, selref cell 0x004f3774 -> 0x00e7d638, objc_msgSend from .got 0x0105b7a0 (cell 0x004f3770 = 0xffffbcac), PIC base 0x0105faf4 (cell 0x004f377c). Single `blx ip` at 0x004f3764; the sender argument is spilled and unused; frame uses the `add fp,sp,#8` / `sub sp,fp,#8` variant.'),
    ),
    dict(
        name='mwou_29',
        method='MultiplayerWorldOptionsUI -[startTouch:tapCount:]',
        types='c20@0:4{CGPoint=ff}8i16',
        start=5187964,
        end=5189108,
        disasm='disasm_worldtileloader_mwou_29.txt',
        base_add=5187980,
        base_literal=5189104,
        boundary='ARM.exidx end 0x004f2df4 (listing bound); next ObjC IMP 0x004f2df4 MultiplayerWorldOptionsUI -[moveTouch:]',
        selectors={
                 0x4f2dc0: (15193636, 'startTouch:'),
                 0x4f2de8: (15193632, 'startTouch:tapCount:'),
        },
        imports={},
        ivars={
                 0x4f2dac: (17155464, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI', 12),
                 0x4f2db0: (17155432, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customGameRulesUI', 180),
                 0x4f2db4: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
                 0x4f2dbc: (17155368, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.OKButton', 120),
                 0x4f2dc4: (17155404, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.pvpButton', 128),
                 0x4f2dc8: (17155416, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditButton', 140),
                 0x4f2dcc: (17155420, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.serverWelcomeButton', 136),
                 0x4f2dd0: (17155424, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.privacyControl', 144),
                 0x4f2dd4: (17155428, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordToggleButton', 152),
                 0x4f2dd8: (17155444, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.passwordSetButton', 156),
                 0x4f2ddc: (17155448, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.ownerPortalButton', 160),
                 0x4f2de0: (17155452, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customRulesButton', 164),
        },
        classes={},
        instructions=[(5187964, 'push {r4, r5, fp, lr}'), (5189104, 'adcseq sp, r6, r0, ror 2')],
        calls=[(5188132, 'bl loc.imp.objc_msgSend'), (5188268, 'bl loc.imp.objc_msgSend'), (5188432, 'bl loc.imp.objc_msgSend'), (5188504, 'bl loc.imp.objc_msgSend'), (5188576, 'bl loc.imp.objc_msgSend'), (5188648, 'bl loc.imp.objc_msgSend'), (5188720, 'bl loc.imp.objc_msgSend'), (5188792, 'bl loc.imp.objc_msgSend'), (5188864, 'bl loc.imp.objc_msgSend'), (5188936, 'bl loc.imp.objc_msgSend'), (5189008, 'bl loc.imp.objc_msgSend')],
        branches=[(5188044, 'beq', 5188144), (5188140, 'b', 5189024), (5188180, 'beq', 5188280), (5188276, 'b', 5189024)],
        semantics=('MultiplayerWorldOptionsUI -[startTouch:tapCount:] @0x004f297c (286 words, 4 branches, 11 calls; read) - touch-down router, the head of the trio with moveTouch:/endTouch:. types c20@0:4{CGPoint=ff}8i16: the tapCount arrives on the stack ([fp,8]) and is re-passed only to the two child UIs. (a) `beq 0x4f2a30` if self->_addCreditUI@12 == nil, else `[self->_addCreditUI startTouch:tapCount:]` (selref cell 0x004f2de8 -> 0x00e7d620; `bl loc.imp.objc_msgSend` 0x004f2a24) with the raw CGPoint in r2/r3 and tapCount re-pushed at [sp]; (b) then `beq 0x4f2ab8` if self->_customGameRulesUI@180 == nil, else `[self->_customGameRulesUI startTouch:tapCount:]` (`bl` 0x004f2aac); both forwards store their reply and `b 0x4f2da0` straight to the epilogue - while a child UI is up it swallows every touch. (c) otherwise: handled = 0 ([fp,-0x39]), the point is converted once to window-local space (windowInfo@112 cell 0x004f2db4 -> slot 0x0105c530, `vldr/vsub.f32` of [+8]/[+0xc]) and `startTouch:` (selref cell 0x004f2dc0 -> 0x00e7d624) is dispatched to the same nine controls in the same address order as the twins: OKButton@120 (cell 0x004f2dbc; `bl` 0x004f2b50), pvpButton@128 (0x004f2dc4; 0x4f2b98), addCreditButton@140 (0x004f2dc8; 0x4f2be0), serverWelcomeButton@136 (0x004f2dcc; 0x4f2c28), privacyControl@144 (0x004f2dd0; 0x4f2c70), passwordToggleButton@152 (0x004f2dd4; 0x4f2cb8), passwordSetButton@156 (0x004f2dd8; 0x4f2d00), ownerPortalButton@160 (0x004f2ddc; 0x4f2d48), customRulesButton@164 (0x004f2de0; 0x4f2d90). The nine replies are spilled to descending stack slots and never folded back into the flag, so the local path returns the constant 0 (`ldrsb r0,[fp,-9]`); the child-UI paths return that child\'s reply. All 11 sends are PLT (`bl loc.imp.objc_msgSend`), no GOT-cached form and no super call.'),
    ),
    dict(
        name='mwou_30',
        method='MultiplayerWorldOptionsUI -[textField:shouldChangeCharactersInRange:replacementString:]',
        types='c24@0:4@8{_NSRange=II}12@20',
        start=5192536,
        end=5192720,
        disasm='disasm_worldtileloader_mwou_30.txt',
        base_add=5192592,
        base_literal=5192712,
        boundary='ARM.exidx end 0x004f3c10 (listing bound); next ObjC IMP 0x004f3c10 MultiplayerWorldOptionsUI -[alertView:didDismissWithButtonIndex:]',
        selectors={
                 0x4f3c04: (15193668, 'text'),
                 0x4f3c0c: (15193672, 'length'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(5192536, 'push {fp, lr}'), (5192716, 'invalid')],
        calls=[(5192604, 'bl loc.imp.objc_msgSend'), (5192628, 'bl loc.imp.objc_msgSend'), (5192660, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[textField:shouldChangeCharactersInRange:replacementString:] @0x004f3b58 (46 words, 0 branches, 3 calls; read) - password-field length clamp. types c24@0:4@8{_NSRange=II}12@20: arg1 textField in [sp,0x14], the NSRange in r3 + stack word (location r3 -> [fp,-8] dead, length -> [fp,-4]), replacementString -> [sp,0x10]. Three PLT sends (`bl loc.imp.objc_msgSend` at 0x004f3b9c / 0x004f3bb4 / 0x004f3bd4): 1 `[textField text]` (selref cell 0x004f3c04 -> 0x00e7d644 \'text\'), 2 `[[textField text] length]` (cell 0x004f3c0c -> 0x00e7d648 \'length\'), 3 `[replacementString length]`. New length = textLen + replacementLen - range.length, then `cmp r0,#0x11; movwlo r2,#1; sxtb r0,r2` -> the edit is accepted only while the resulting length stays below 17 characters.'),
    ),
    dict(
        name='mwou_31',
        method='MultiplayerWorldOptionsUI -[textFieldShouldReturn:]',
        types='c12@0:4@8',
        start=5193608,
        end=5193740,
        disasm='disasm_worldtileloader_mwou_31.txt',
        base_add=5193624,
        base_literal=5193736,
        boundary='ARM.exidx end 0x004f400c (listing bound); next ObjC IMP 0x004f400c MultiplayerWorldOptionsUI -[displayPasswordEntry]',
        selectors={
                 0x4f4000: (15193580, 'dismissWithClickedButtonIndex:animated:'),
        },
        imports={
                 0x4f3ffc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f4004: (17155460, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.textEntryAlertView', 168),
        },
        classes={},
        instructions=[(5193608, 'push {r4, r5, r6, sl, fp, lr}'), (5193736, 'adcseq fp, r6, r4, asr fp')],
        calls=[(5193704, 'blx r4')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[textFieldShouldReturn:] @0x004f3f88 (33 words, 0 branches, 1 call; read) - return-key handler: `[self->_textEntryAlertView@168 dismissWithClickedButtonIndex:1 animated:1]`, then returns YES. Both button index and animated flag are `movw #1` constants (ip = buttonIndex, lr = animated; r2 = 1, r3 = sxtb(1)); selref cell 0x004f4000 -> 0x00e7d5ec \'dismissWithClickedButtonIndex:animated:\', alert ivar cell 0x004f4004 -> slot 0x0105c584 -> 168, objc_msgSend from .got 0x0105b7a0 (cell 0x004f3ffc), single `blx r4` at 0x004f3fe8; the incoming textField argument is spilled to [sp,4] and never read, and the return value is the spilled constant 1 (`ldr r0,[sp]; sxtb`).'),
    ),
    dict(
        name='mwou_32',
        method='MultiplayerWorldOptionsUI -[touchIsInUI:]',
        types='c16@0:4{CGPoint=ff}8',
        start=5187836,
        end=5187964,
        disasm='disasm_worldtileloader_mwou_32.txt',
        base_add=5187848,
        base_literal=5187960,
        boundary='ARM.exidx end 0x004f297c (listing bound); next ObjC IMP 0x004f297c MultiplayerWorldOptionsUI -[startTouch:tapCount:]',
        selectors={},
        imports={},
        ivars={
                 0x4f2974: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
        },
        classes={},
        instructions=[(5187836, 'push {r4, lr}'), (5187960, 'adcseq sp, r6, r4, ror 3')],
        calls=[],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[touchIsInUI:] @0x004f28fc (32 words, 0 branches, 0 calls; read) - constant NO with dead float work. types c16@0:4{CGPoint=ff}8 (point in r2/r3). Reads windowInfo@112 (offset cell 0x004f2974 -> slot 0x0105c530, PIC base 0x0105faf4 from cell 0x004f2978), dereferences it and computes (p.x - windowInfo[+8]) and (p.y - windowInfo[+0xc]) with `vldr/vsub.f32/vstr` into [sp]/[sp,4] - a window-local point conversion whose results are never read - then returns the constant `movw lr,#0; sxtb r0,lr`. No message send and no selector anywhere in the body.'),
    ),
    dict(
        name='mwou_33',
        method='MultiplayerWorldOptionsUI -[touchIsInViewAtAll:]',
        types='c16@0:4{CGPoint=ff}8',
        start=5187708,
        end=5187836,
        disasm='disasm_worldtileloader_mwou_33.txt',
        base_add=5187720,
        base_literal=5187832,
        boundary='ARM.exidx end 0x004f297c; body trimmed at the next IMP 0x004f28fc MultiplayerWorldOptionsUI -[touchIsInUI:]',
        selectors={},
        imports={},
        ivars={
                 0x4f28f4: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
        },
        classes={},
        instructions=[(5187708, 'push {r4, lr}'), (5187832, 'adcseq sp, r6, r4, ror 4')],
        calls=[],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[touchIsInViewAtAll:] @0x004f287c (32 words, 0 branches, 0 calls; read; roster-trimmed) - constant YES with the same dead float work as touchIsInUI:. windowInfo@112 via offset cell 0x004f28f4 -> slot 0x0105c530 (PIC base from cell 0x004f28f8), (p.x - windowInfo[+8]) / (p.y - windowInfo[+0xc]) computed with vldr/vsub.f32/vstr into [sp]/[sp,4] and discarded; return is the constant `movw lr,#1; sxtb r0,lr`. Byte-for-byte the same 32-word shape as mwou_32 apart from the constant, the pool values and the per-body addresses.'),
    ),
    dict(
        name='mwou_34',
        method='MultiplayerWorldOptionsUI -[windowInfoChanged:]',
        types='v12@0:4^{WindowInfo=ffffffff}8',
        start=5180872,
        end=5181308,
        disasm='disasm_worldtileloader_mwou_34.txt',
        base_add=5180892,
        base_literal=5181304,
        boundary='ARM.exidx end 0x004f0f7c (listing bound); next ObjC IMP 0x004f0f7c MultiplayerWorldOptionsUI -[render:]',
        selectors={
                 0x4f0f64: (15193592, 'windowInfoChanged:'),
        },
        imports={
                 0x4f0f60: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f0f68: (17155432, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.customGameRulesUI', 180),
                 0x4f0f6c: (17155464, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.addCreditUI', 12),
                 0x4f0f70: (17155396, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.orthoMatrix', 48),
                 0x4f0f74: (17155376, 'OBJC_IVAR_$_MultiplayerWorldOptionsUI.windowInfo', 112),
        },
        classes={},
        instructions=[(5180872, 'push {r4, r5, r6, sl, fp, lr}'), (5181304, 'adcseq lr, r6, r0, lsl sp')],
        calls=[(5181092, 'bl 0x4f05dc'), (5181188, 'bl sym.imp.memcpy'), (5181228, 'blx ip'), (5181268, 'blx ip')],
        branches=[],
        semantics=('MultiplayerWorldOptionsUI -[windowInfoChanged:] @0x004f0dc8 (109 words, 0 branches, 4 calls; read) - layout forwarding. Stores the incoming WindowInfo* straight into windowInfo@112 (`str r2` through offset cell 0x004f0f74 -> slot 0x0105c530; note this is a plain store, no ARC helper), then recomputes the ortho matrix: it loads windowInfo[+8] / windowInfo[+0xc] (vldr/vneg.f32) and materialises a 3-float local struct {windowInfo[+0xc], 1000.0f (0x447a0000), -1000.0f (0xc47a0000)} at [sp], calls the in-image helper 0x004f05dc (`bl 0x004f05dc` at 0x004f0ea4; dest = [sp+0x30], args -wi.x / +wi.x / -wi.y - an ortho/projection matrix builder) and `bl sym.imp.memcpy` with size 0x40 copies the 64-byte result into orthoMatrix@48 (offset cell 0x004f0f70 -> slot 0x0105c544). Then two forwarding sends with the new pointer as argument: `[self->_addCreditUI@12 windowInfoChanged:wi]` (`blx ip` 0x004f0f2c, cell 0x004f0f6c -> slot 0x0105c588) and `[self->_customGameRulesUI@180 windowInfoChanged:wi]` (`blx ip` 0x004f0f54, cell 0x004f0f68 -> slot 0x0105c568), both with selref cell 0x004f0f64 -> 0x00e7d5f8 and objc_msgSend from .got 0x0105b7a0 (cell 0x004f0f60). No super call (no msgSendSuper2 import in this body).'),
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
        'batch': 'MultiplayerWorldOptionsUI (E158): the multiplayer world options screen; 35 bodies',
        'claim': ('\'the multiplayer world options overlay (the password/PvP/welcome toggles, the credit top-up and owner-portal buttons, the custom-rules and privacy flows, the alert routing); the multiplayer session itself is outside these bodies\''),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldoptions.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldoptions.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
