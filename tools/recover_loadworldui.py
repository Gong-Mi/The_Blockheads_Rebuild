#!/usr/bin/env python3
"""Hash-gated recovery of the LoadWorldUI (E157).

The load-world screen lands: the batch sweeps the load-world screen surface:
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
reconstruction/reverse-v3/native/LOADWORLDUI.md for the prose and boundaries.
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
    'bl 0x7ed878': 0x007ed878,
    'bl 0x7ed8c4': 0x007ed8c4,
    'bl 0x7ed910': 0x007ed910,
    'bl 0x7f633c': 0x007f633c,
    'bl 0x806a94': 0x00806a94,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.constructor.Vector2.Vector2_float__float_': 0x004d0480,
    'bl sym.UIGraphicsBeginImageContextWithOptions': 0x002558d4,
    'bl sym.UIGraphicsEndImageContext': 0x00255b6c,
    'bl sym.UIGraphicsGetImageFromCurrentImageContext': 0x00255dd0,
    'bl sym.UIImagePNGRepresentation': 0x00264ce4,
    'bl sym.imp.NSSearchPathForDirectoriesInDomains': 0x001c3f20,
    'bl sym.imp.__aeabi_memcpy': 0x001c3c08,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.__wrap_malloc': 0x001c2e58,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
}

SPECS = [
    dict(
        name='lwu_00',
        method='LoadWorldUI -[alertView:didDismissWithButtonIndex:]',
        types='v16@0:4@8i12',
        start=8410452,
        end=8413340,
        disasm='disasm_worldtileloader_lwu_00.txt',
        base_add=8410468,
        base_literal=8413336,
        boundary='ARM.exidx end 0x0080609c (listing bound); next ObjC IMP 0x0080609c LoadWorldUI -[textFieldShouldReturn:]',
        selectors={
                 0x806000: (15211492, 'canOpenURL:'),
                 0x806004: (15211488, 'sharedApplication'),
                 0x80600c: (15211484, 'URLWithString:'),
                 0x806018: (15211228, 'stringWithFormat:'),
                 0x80601c: (15211424, 'text'),
                 0x806020: (15211480, 'stringByAddingPercentEscapesUsingEncoding:'),
                 0x806024: (15211476, 'title'),
                 0x80602c: (15211444, 'textFieldAtIndex:'),
                 0x806030: (15211496, 'openURL:'),
                 0x806038: (15211472, 'showToastWithMessage:duration:'),
                 0x806040: (15211216, 'setString:'),
                 0x806044: (15211468, 'generalPasteboard'),
                 0x80604c: (15211188, 'autorelease'),
                 0x806050: (15211464, 'setDelegate:'),
                 0x806058: (15211448, 'isEqualToString:'),
                 0x80605c: (15211284, 'length'),
                 0x806060: (15211348, 'uppercaseString'),
                 0x806064: (15211452, 'substringToIndex:'),
                 0x806070: (15211460, 'setObject:forKey:'),
                 0x806078: (15211160, 'standardUserDefaults'),
                 0x806080: (15211176, 'retain'),
                 0x806084: (15211256, 'setTitle:'),
                 0x80608c: (15211456, 'renameCurrentWorld:'),
        },
        imports={
                 0x805ffc: (17151904, 'objc_msgSend'),
                 0x806014: (16325624, '__CFConstantStringClassReference'),
                 0x806034: (16325608, '__CFConstantStringClassReference'),
                 0x806054: (16324600, '__CFConstantStringClassReference'),
                 0x80606c: (16324744, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x805ff4: (17161036, 'OBJC_IVAR_$_LoadWorldUI.textEntryAlertView', 64),
                 0x805ff8: (17161040, 'OBJC_IVAR_$_LoadWorldUI.shareTextAlertView', 76),
                 0x806068: (17161044, 'OBJC_IVAR_$_LoadWorldUI.textEntryType', 44),
                 0x806074: (17160924, 'OBJC_IVAR_$_LoadWorldUI.hostUserName', 152),
                 0x806088: (17160960, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameButton', 104),
                 0x806090: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
                 0x806094: (17160980, 'OBJC_IVAR_$_LoadWorldUI.worldNameButton', 84),
        },
        classes={
                 0x806008: (15247296, 'OBJC_CLASS_$_UIApplication'),
                 0x806010: (15247292, 'OBJC_CLASS_$_NSURL'),
                 0x806028: (15247248, 'OBJC_CLASS_$_NSString'),
                 0x80603c: (15247288, 'OBJC_CLASS_$_UIToast'),
                 0x806048: (15247284, 'OBJC_CLASS_$_UIPasteboard'),
                 0x80607c: (15247244, 'OBJC_CLASS_$_NSUserDefaults'),
        },
        instructions=[(8410452, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8413336, 'addeq sl, r5, r8, lsl 11')],
        calls=[(8410636, 'blx lr'), (8410660, 'blx r2'), (8410740, 'blx r2'), (8410760, 'blx r3'), (8410852, 'blx lr'), (8410868, 'blx r2'), (8410892, 'blx r2'), (8410948, 'blx r3'), (8411084, 'blx ip'), (8411124, 'blx ip'), (8411376, 'blx r3'), (8411412, 'blx r3'), (8411444, 'blx r3'), (8411496, 'blx ip'), (8411548, 'blx ip'), (8411672, 'blx r3'), (8411692, 'blx r3'), (8411732, 'blx r3'), (8411768, 'blx r3'), (8412072, 'blx r3'), (8412108, 'blx r3'), (8412148, 'blx r3'), (8412180, 'blx r3'), (8412220, 'blx ip'), (8412548, 'blx r3'), (8412608, 'blx r2'), (8412628, 'blx r3'), (8412660, 'blx r3'), (8412704, 'blx lr'), (8412744, 'blx ip'), (8412780, 'blx r3'), (8412800, 'blx r3'), (8412884, 'blx ip'), (8412904, 'blx r3'), (8413032, 'blx r3'), (8413052, 'blx r3'), (8413092, 'blx r3'), (8413128, 'blx r3')],
        branches=[(8410524, 'bne', 8411804), (8410536, 'bne', 8411560), (8410672, 'beq', 8410776), (8410772, 'beq', 8410780), (8410776, 'b', 8413164), (8410900, 'bls', 8410956), (8410988, 'bne', 8411132), (8411128, 'b', 8411556), (8411164, 'bne', 8411552), (8411552, 'b', 8411556), (8411556, 'b', 8411560), (8411800, 'b', 8413164), (8411840, 'bne', 8413160), (8411852, 'bne', 8412228), (8412224, 'b', 8412920), (8412236, 'bne', 8412916), (8412812, 'beq', 8412912), (8412912, 'b', 8412916), (8412916, 'b', 8412920), (8413160, 'b', 8413164)],
        semantics=('LoadWorldUI -[alertView:didDismissWithButtonIndex:] @0x00805554 (722 words, 38 calls, 20 branches; census-lite) - the class\'s UIAlertView delegate callback; it multiplexes all four LoadWorldUI alert flows by (alertView, buttonIndex). PIC base 0x0105faf4 (pool cell 0x00806098 = 0x85a588 + pc 0x00805564); objc_msgSend cached from GOT 0x0105b7a0 (cell 0x00805ffc, loaded 11x). Head: \'cmp alertView, self->textEntryAlertView@64 (cell 0x00805ff4) -> bne 0x00805a9c\', then \'cmp buttonIndex, #1 -> bne 0x008059a8\'. (A) textEntryAlertView + buttonIndex==1 (0x008055ac..0x00805698): text = [[self->textEntryAlertView textFieldAtIndex:0] text] (sends 1-2); \'cmp r0,#0; beq tail\' (nil check) then send 3-4 \'[text isEqualToString:@""]\' (CFSTR 0x00f917f8, an empty literal) -> \'beq tail\', i.e. an empty entry is ignored; then name = [[text uppercaseString] substringToIndex:16] guarded by \'cmp length,#16; bls\' (sends 5-8: text/uppercaseString/length/substringToIndex:); then dispatch on self->textEntryType@44 (cells 0x00806068, \'cmp #0 / #1\'): type 0 -> [self->worldNameButton@84 setTitle:name] + [self->delegate@4 renameCurrentWorld:name] (sends 9-10); type 1 -> [self->hostNickNameButton@104 setTitle:name], then the ARC strong-assign \'[old autorelease] + [name retain] -> str into self->hostUserName@152\' (sends 11-13) and finally [[NSUserDefaults standardUserDefaults] setObject:self->hostUserName forKey:@"joinUserName" (CFSTR 0x00f91888)] (sends 14-15). (E) textEntryAlertView + other buttonIndex (0x008059a8..0x00805a98): teardown - [textFieldAtIndex:0], [<field> setDelegate:nil], [self->textEntryAlertView setDelegate:nil], [self->textEntryAlertView autorelease] and \'str 0,[self+64]\' to nil the ivar (4 sends). (1) self->shareTextAlertView@76 (cell 0x00805ff8) + buttonIndex==1 (0x00805ad0..0x00805c40): \'Copy\' branch - [[self->shareTextAlertView textFieldAtIndex:0] text], [[UIPasteboard generalPasteboard] setString:link], then [UIToast showToastWithMessage:@"Text copied to clipboard." (CFSTR 0x00f91be8) duration:3] (movw r3,#3) (5 sends). (2) shareTextAlertView + buttonIndex==2 (0x00805c50..0x00805ef0): \'E-mail\' branch - reads the link back out of the alert (textFieldAtIndex:0 / text), builds the mailto URL with [NSString stringWithFormat:@"mailto:?to=&subject=%@&body=Click%%20the%%20link%%20below%%20from%%20your%%20mobile%%20device%%20join%%20my%%20world%%20in%%20The%%20Blockheads!%%0D%%0A%%0D%%0A%@" (CFSTR 0x00f91bf8), using [<alert> title] and the percent-escaped (stringByAddingPercentEscapesUsingEncoding:4) values, then [NSURL URLWithString:], [UIApplication sharedApplication], [app canOpenURL:url] and, only if that is YES, [app openURL:url] (sends - \'sxtb/cmp/beq 0x805ef0\' gate at 0x00805e8c) (9-10 sends). (T) fallthrough tail 0x00805ef8 (buttonIndex 0 / unknown alert): identical teardown for self->shareTextAlertView (textFieldAtIndex:, setDelegate: nil x2, autorelease, ivar nil) (4 sends) then \'sub sp,fp,#0x18; pop {r4,r5,r6,r7,r8,sl,fp,pc}\'.'),
    ),
    dict(
        name='lwu_01',
        method='LoadWorldUI -[backButton:]',
        types='v12@0:4@8',
        start=8381852,
        end=8382188,
        disasm='disasm_worldtileloader_lwu_01.txt',
        base_add=8381860,
        base_literal=8382184,
        boundary='ARM.exidx end 0x007fe6ec (listing bound); next ObjC IMP 0x007fe6ec LoadWorldUI -[deleteWorldButton:]',
        selectors={},
        imports={},
        ivars={
                 0x7fe6e4: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
        },
        classes={},
        instructions=[(8381852, 'sub sp, sp, 0x10'), (8382184, 'addeq r1, r6, r8, asr 10')],
        calls=[],
        branches=[(8381908, 'bne', 8381948), (8381944, 'b', 8382172), (8381980, 'bne', 8382020), (8382016, 'b', 8382168), (8382052, 'bne', 8382092), (8382088, 'b', 8382164), (8382124, 'bne', 8382160), (8382160, 'b', 8382164), (8382164, 'b', 8382168), (8382168, 'b', 8382172)],
        semantics=('LoadWorldUI -[backButton:] @0x007fe59c (84 words, 10 branches, 0 calls): pure state-ivar adjuster with no message sends at all. The argument is spilled to [sp,4] and never read. It loads OBJC_IVAR_$_LoadWorldUI.state@40 through the Apportable offset cell 0x007fe6e4 (base = pc+0x861548 -> 0x105faf4, slot at base-0x2038 -> 0x105dabc -> ptr 0xf33c98 -> word 0x28) and rewrites it as a step-back mapping: state==1 -> 0, state==2 -> 0, state==3 -> 1, state==4 -> 3; any other value is left untouched (all four tails converge on the shared epilogue add sp,sp,0x10; bx lr). No UI refresh happens here - the render pass reads self->state.'),
    ),
    dict(
        name='lwu_02',
        method='LoadWorldUI -[cloudConnectionCancelled]',
        types='v8@0:4',
        start=8419768,
        end=8419868,
        disasm='disasm_worldtileloader_lwu_02.txt',
        base_add=8419784,
        base_literal=8419864,
        boundary='ARM.exidx end 0x00807a1c (listing bound); next ObjC IMP 0x00807a1c LoadWorldUI -[onlineOwnerPortalButton:]',
        selectors={
                 0x807a10: (15211572, 'multiplayerGameSelectCancelled'),
        },
        imports={
                 0x807a0c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x807a14: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
        },
        classes={},
        instructions=[(8419768, 'push {fp, lr}'), (8419864, 'addeq r8, r5, r4, lsr 2')],
        calls=[(8419840, 'blx r3')],
        branches=[],
        semantics=('LoadWorldUI -[cloudConnectionCancelled] @0x008079b8 (25 words, 0 branches, 1 call): Apportable offset-cell stub - the frame (push {fp,lr}/sub sp,#8) only spills self and _cmd to [sp,4]/[sp]. It builds the PIC base 0x0105faf4 from pool cell 0x00807a18 (0x858124 + pc at 0x008079c8), reads objc_msgSend out of .got slot 0x0105b7a0 (pool cell 0x00807a0c = 0xffffbcac), the selref for @selector(multiplayerGameSelectCancelled) at 0x00e81c34 (pool cell 0x00807a10 = 0xffe22140) and the delegate ivar-offset cell OBJC_IVAR_$_LoadWorldUI.delegate@4 (.got 0x0105dac8 via pool cell 0x00807a14 = 0xffffdfd4), then issues the single send objc_msgSend(self->delegate@4, @selector(multiplayerGameSelectCancelled)) with blx r3 at 0x00807a00 and returns. The delegate callback is the only effect; the value is not used.'),
    ),
    dict(
        name='lwu_03',
        method='LoadWorldUI -[cloudConnectionFailed:presentTopupUI:]',
        types='v16@0:4i8c12',
        start=8419356,
        end=8419768,
        disasm='disasm_worldtileloader_lwu_03.txt',
        base_add=8419372,
        base_literal=8419764,
        boundary='ARM.exidx end 0x008079b8 (listing bound); next ObjC IMP 0x008079b8 LoadWorldUI -[cloudConnectionCancelled]',
        selectors={
                 0x807994: (15211572, 'multiplayerGameSelectCancelled'),
                 0x8079a0: (15211576, 'presentAddCreditUIForWorldWithName:worldID:currentCredit:'),
                 0x8079a8: (15211224, 'objectForKey:'),
        },
        imports={
                 0x807990: (17151904, 'objc_msgSend'),
                 0x8079a4: (16324808, '__CFConstantStringClassReference'),
                 0x8079b0: (16325336, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x807998: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
                 0x8079ac: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
        },
        classes={},
        instructions=[(8419356, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8419764, 'addeq r8, r5, r0, asr 5')],
        calls=[(8419440, 'blx lr'), (8419616, 'blx r6'), (8419668, 'blx ip'), (8419716, 'blx ip')],
        branches=[(8419452, 'beq', 8419720)],
        semantics=('LoadWorldUI -[cloudConnectionFailed:presentTopupUI:] @0x0080781c (103 words, 1 branch, 4 calls): cloud-connection failure callback (types v16@0:4i8c12 -> arg1 int at fp-0x20, arg2 BOOL at fp-0x25, both only the BOOL is read). Always first sends [self->delegate@4 multiplayerGameSelectCancelled] through the objc_msgSend GOT slot 0x00807990 (blx lr). Then ldrsb the presentTopupUI flag; if NO, jumps straight to the epilogue. If YES it builds the top-up request: worldName = [self->gameSave@36 objectForKey:@"worldName"] (blx r6; constant-string struct at T+0xfff31fe4=0x00f91ad8, cstr \'worldName\', len 9) and saveID = [self->gameSave objectForKey:@"saveID"] (blx ip; struct at T+0xfff31dd4=0x00f918c8, cstr \'saveID\', len 6), then sends [self->delegate presentAddCreditUIForWorldWithName:worldName worldID:saveID currentCredit:0.0f] (blx ip) - the float is the literal pool word 0x00000000 (0.0f) at 0x0080799c, passed as a stack argument (str ip,[sp]) after vmov ip,s0. All 3 sends go through one cached objc_msgSend fn pointer (slots filled from T=pc+0x8582c0=0x0105faf4).'),
    ),
    dict(
        name='lwu_04',
        method='LoadWorldUI -[cloudConnectionRequestSucceededWithHost:port:key:]',
        types='v20@0:4@8@12@16',
        start=8419016,
        end=8419356,
        disasm='disasm_worldtileloader_lwu_04.txt',
        base_add=8419032,
        base_literal=8419352,
        boundary='ARM.exidx end 0x0080781c (listing bound); next ObjC IMP 0x0080781c LoadWorldUI -[cloudConnectionFailed:presentTopupUI:]',
        selectors={
                 0x807800: (15211568, 'joinCloudWorldAtHost:port:key:userName:pic:'),
                 0x80780c: (15211224, 'objectForKey:'),
        },
        imports={
                 0x8077fc: (17151904, 'objc_msgSend'),
                 0x807808: (16324888, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x807804: (17161004, 'OBJC_IVAR_$_LoadWorldUI.hostUserPhoto', 156),
                 0x807810: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
                 0x807814: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
        },
        classes={},
        instructions=[(8419016, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8419352, 'addeq r8, r5, r4, lsl r4')],
        calls=[(8419224, 'blx r4'), (8419312, 'blx r6')],
        branches=[],
        semantics=('LoadWorldUI -[cloudConnectionRequestSucceededWithHost:port:key:] @0x008076c8 (85 words, 0 branches, 2 calls): success callback for the cloud host request. Arg layout per types v20@0:4@8@12@16: host=r2, port=r3, key=stack [fp,8]; all spilled to fp-0x1c..-0x2c. First send: userName = [self->gameSave@36 objectForKey:@"userName"] (objc_msgSend via GOT slot 0x008077fc -> blx r4; const-string \'userName\' struct at T+0xfff31e24=0x00f91918). Second send (through the cached msgSend ptr in r6, blx r6): [self->delegate@4 joinCloudWorldAtHost:host port:port key:key userName:userName pic:self->hostUserPhoto@156] - 5th/6th/7th args (key, userName, pic) are stack-marshalled (str ip,[sp], str r4,[sp,4], str r5,[sp,8]); pic comes from ivar cell 0x00807804 (hostUserPhoto, offset 156). SELs: joinCloudWorldAtHost:port:key:userName:pic: (0x00807800), objectForKey: (0x0080780c).'),
    ),
    dict(
        name='lwu_05',
        method='LoadWorldUI -[currentWorldChanged:]',
        types='v12@0:4@8',
        start=8337104,
        end=8348476,
        disasm='disasm_worldtileloader_lwu_05.txt',
        base_add=8337120,
        base_literal=8339988,
        boundary='ARM.exidx end 0x007f633c (listing bound); next ObjC IMP 0x007f6428 LoadWorldUI -[renderFrame:projectionMatrix:]',
        selectors={
                 0x7f4220: (15211220, 'setGlyphTexture:'),
                 0x7f4230: (15211196, 'release'),
                 0x7f4240: (15211176, 'retain'),
                 0x7f4244: (15211188, 'autorelease'),
                 0x7f4924: (15211236, 'fileExistsAtPath:'),
                 0x7f4928: (15211232, 'defaultManager'),
                 0x7f4934: (15211228, 'stringWithFormat:'),
                 0x7f493c: (15211224, 'objectForKey:'),
                 0x7f4944: (15211208, 'objectAtIndex:'),
                 0x7f4a60: (15211240, 'stringByAppendingPathComponent:'),
                 0x7f4a64: (15211244, 'imageWithContentsOfFile:'),
                 0x7f4c58: (15211248, 'initWithUIImage:'),
                 0x7f4c5c: (15211120, 'alloc'),
                 0x7f4d98: (15211252, 'boolValue'),
                 0x7f4da8: (15211256, 'setTitle:'),
                 0x7f4ecc: (15211168, 'setHidden:'),
                 0x7f53cc: (15211260, 'countByEnumeratingWithState:objects:count:'),
                 0x7f53d0: (15211116, 'init'),
                 0x7f5734: (15211204, 'count'),
                 0x7f5738: (15211264, 'getBytes:length:'),
                 0x7f5a44: (15211276, 'addObject:'),
                 0x7f5a48: (15211272, 'setWalking:'),
                 0x7f5a54: (15211268, 'initWithFrame:cache:windowInfo:'),
                 0x7f5ca0: (15211212, 'setFrame:'),
                 0x7f5ca8: (15211292, 'initWithBytes:length:encoding:'),
                 0x7f5cac: (15211280, 'setFromPreviewData:'),
                 0x7f5cb4: (15211284, 'length'),
                 0x7f5cb8: (15211288, 'getBytes:range:'),
                 0x7f617c: (15211296, 'stringByAppendingFormat:'),
                 0x7f62c0: (15211188, 'autorelease'),
                 0x7f62c4: (15211208, 'objectAtIndex:'),
                 0x7f62cc: (15211120, 'alloc'),
                 0x7f62d0: (15211260, 'countByEnumeratingWithState:objects:count:'),
                 0x7f62d4: (15211116, 'init'),
                 0x7f62dc: (15211204, 'count'),
                 0x7f62e0: (15211264, 'getBytes:length:'),
                 0x7f62e8: (15211212, 'setFrame:'),
                 0x7f62f4: (15211276, 'addObject:'),
                 0x7f62f8: (15211272, 'setWalking:'),
                 0x7f6304: (15211268, 'initWithFrame:cache:windowInfo:'),
                 0x7f6310: (15211292, 'initWithBytes:length:encoding:'),
                 0x7f6314: (15211280, 'setFromPreviewData:'),
                 0x7f631c: (15211284, 'length'),
                 0x7f6320: (15211288, 'getBytes:range:'),
                 0x7f6328: (15211296, 'stringByAppendingFormat:'),
                 0x7f6334: (15211216, 'setString:'),
        },
        imports={
                 0x7f421c: (17151904, 'objc_msgSend'),
                 0x7f4930: (16324792, '__CFConstantStringClassReference'),
                 0x7f4938: (16324824, '__CFConstantStringClassReference'),
                 0x7f4940: (16324808, '__CFConstantStringClassReference'),
                 0x7f4a5c: (16324840, '__CFConstantStringClassReference'),
                 0x7f4d9c: (16324856, '__CFConstantStringClassReference'),
                 0x7f4da4: (16324904, '__CFConstantStringClassReference'),
                 0x7f4db0: (16324872, '__CFConstantStringClassReference'),
                 0x7f4db4: (16324888, '__CFConstantStringClassReference'),
                 0x7f4ed4: (16324920, '__CFConstantStringClassReference'),
                 0x7f4ed8: (16324952, '__CFConstantStringClassReference'),
                 0x7f4edc: (16324936, '__CFConstantStringClassReference'),
                 0x7f4ee0: (16324968, '__CFConstantStringClassReference'),
                 0x7f5270: (16324984, '__CFConstantStringClassReference'),
                 0x7f5274: (16325000, '__CFConstantStringClassReference'),
                 0x7f52dc: (16324616, '__CFConstantStringClassReference'),
                 0x7f53bc: (16325016, '__CFConstantStringClassReference'),
                 0x7f53c0: (16325032, '__CFConstantStringClassReference'),
                 0x7f53c4: (16325048, '__CFConstantStringClassReference'),
                 0x7f53c8: (16325064, '__CFConstantStringClassReference'),
                 0x7f616c: (16325080, '__CFConstantStringClassReference'),
                 0x7f6170: (16325096, '__CFConstantStringClassReference'),
                 0x7f6174: (16325112, '__CFConstantStringClassReference'),
                 0x7f6178: (17151904, 'objc_msgSend'),
                 0x7f6180: (16325128, '__CFConstantStringClassReference'),
                 0x7f62b4: (16325144, '__CFConstantStringClassReference'),
                 0x7f62b8: (17151904, 'objc_msgSend'),
                 0x7f6308: (16325080, '__CFConstantStringClassReference'),
                 0x7f630c: (16325096, '__CFConstantStringClassReference'),
                 0x7f6324: (16325144, '__CFConstantStringClassReference'),
                 0x7f632c: (16325128, '__CFConstantStringClassReference'),
                 0x7f6330: (16325112, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7f4218: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
                 0x7f4224: (17160952, 'OBJC_IVAR_$_LoadWorldUI.hostPicButton', 112),
                 0x7f4228: (17161020, 'OBJC_IVAR_$_LoadWorldUI.onlinePicButton', 132),
                 0x7f422c: (17161000, 'OBJC_IVAR_$_LoadWorldUI.picTexture', 148),
                 0x7f4234: (17161004, 'OBJC_IVAR_$_LoadWorldUI.hostUserPhoto', 156),
                 0x7f4238: (17161008, 'OBJC_IVAR_$_LoadWorldUI.blockheadPreviews', 32),
                 0x7f423c: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x7f4da0: (17160920, 'OBJC_IVAR_$_LoadWorldUI.disabledTextView', 56),
                 0x7f4dac: (17160912, 'OBJC_IVAR_$_LoadWorldUI.playButton', 20),
                 0x7f4ed0: (17160916, 'OBJC_IVAR_$_LoadWorldUI.optionsButton', 24),
                 0x7f573c: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7f5a4c: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
                 0x7f62bc: (17161008, 'OBJC_IVAR_$_LoadWorldUI.blockheadPreviews', 32),
                 0x7f62e4: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7f62fc: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
                 0x7f6338: (17160908, 'OBJC_IVAR_$_LoadWorldUI.blockheadNamesTextView', 28),
        },
        classes={
                 0x7f4920: (15247248, 'OBJC_CLASS_$_NSString'),
                 0x7f492c: (15247252, 'OBJC_CLASS_$_NSFileManager'),
                 0x7f4a68: (15247256, 'OBJC_CLASS_$_UIImage'),
                 0x7f4c60: (15247260, 'OBJC_CLASS_$_CPTexture2D'),
                 0x7f53d4: (15247264, 'OBJC_CLASS_$_NSMutableArray'),
                 0x7f5740: (15247268, 'OBJC_CLASS_$_BlockheadPreviewView'),
                 0x7f62c8: (15247248, 'OBJC_CLASS_$_NSString'),
                 0x7f62d8: (15247264, 'OBJC_CLASS_$_NSMutableArray'),
                 0x7f62f0: (15247268, 'OBJC_CLASS_$_BlockheadPreviewView'),
        },
        instructions=[(8337104, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8348472, 'invalid')],
        calls=[(8337352, 'blx r4'), (8337384, 'blx r3'), (8337464, 'blx r4'), (8337524, 'blx lr'), (8337584, 'blx lr'), (8337644, 'blx lr'), (8337684, 'blx r3'), (8337756, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (8337976, 'blx r3'), (8338028, 'blx ip'), (8338080, 'blx ip'), (8338132, 'blx r4'), (8338168, 'blx r3'), (8338188, 'blx r3'), (8338220, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (8338292, 'blx r3'), (8338312, 'blx r3'), (8338384, 'blx r3'), (8338452, 'blx r2'), (8338652, 'blx r8'), (8338688, 'blx r3'), (8338760, 'blx ip'), (8338816, 'blx lr'), (8338928, 'blx ip'), (8338944, 'blx r2'), (8339168, 'blx ip'), (8339204, 'blx ip'), (8339248, 'blx r3'), (8339396, 'blx r5'), (8339440, 'blx ip'), (8339484, 'blx ip'), (8339644, 'blx r5'), (8339688, 'blx ip'), (8339732, 'blx ip'), (8339816, 'blx r3'), (8339936, 'blx ip'), (8339952, 'blx r2'), (8340144, 'blx ip'), (8340160, 'blx r2'), (8340276, 'blx ip'), (8340360, 'blx r3'), (8340484, 'blx lr'), (8340528, 'blx ip'), (8340632, 'blx ip'), (8340772, 'blx lr'), (8340816, 'blx ip'), (8340920, 'blx ip'), (8341088, 'blx r2'), (8341104, 'blx r2'), (8341156, 'bl sym.imp.memset'), (8341204, 'blx lr'), (8341304, 'bl sym.imp.objc_enumerationMutation'), (8341432, 'blx r4'), (8341492, 'blx r2'), (8341580, 'blx r3'), (8341688, 'blx r3'), (8341784, 'bl 0x7ed878'), (8342004, 'blx r3'), (8342100, 'bl 0x7ed878'), (8342188, 'blx r3'), (8342284, 'bl 0x7ed878'), (8342520, 'bl loc.imp.objc_msgSend'), (8342536, 'blx r2'), (8342568, 'blx r3'), (8342608, 'blx ip'), (8342716, 'blx r3'), (8342832, 'blx r3'), (8342928, 'bl 0x7ed878'), (8343140, 'blx r3'), (8343236, 'bl 0x7ed878'), (8343328, 'blx r3'), (8343424, 'bl 0x7ed878'), (8343480, 'bl loc.imp.objc_msgSend'), (8343596, 'bl sym.imp.__aeabi_memcpy'), (8343712, 'bl loc.imp.objc_msgSend'), (8343732, 'bl loc.imp.objc_msgSend'), (8343744, 'bl sym.imp.__wrap_malloc'), (8343828, 'bl loc.imp.objc_msgSend'), (8343860, 'blx r3'), (8343892, 'blx lr'), (8343908, 'blx r2'), (8343920, 'bl sym.imp.__wrap_free'), (8344008, 'blx r2'), (8344068, 'blx r2'), (8344164, 'blx ip'), (8344272, 'blx ip'), (8344356, 'blx ip'), (8344476, 'blx ip'), (8344692, 'blx r2'), (8344708, 'blx r2'), (8344760, 'bl sym.imp.memset'), (8344808, 'blx lr'), (8344908, 'bl sym.imp.objc_enumerationMutation'), (8345036, 'blx r4'), (8345096, 'blx r2'), (8345184, 'blx r3'), (8345292, 'blx r3'), (8345388, 'bl 0x7ed878'), (8345584, 'blx r3'), (8345680, 'bl 0x7ed878'), (8345752, 'blx r3'), (8345848, 'bl 0x7ed878'), (8346084, 'bl loc.imp.objc_msgSend'), (8346100, 'blx r2'), (8346132, 'blx r3'), (8346172, 'blx ip'), (8346288, 'blx r3'), (8346404, 'blx r3'), (8346500, 'bl 0x7ed878'), (8346680, 'blx r3'), (8346776, 'bl 0x7ed878'), (8346872, 'blx r3'), (8346968, 'bl 0x7ed878'), (8347024, 'bl loc.imp.objc_msgSend'), (8347328, 'bl 0x7f633c'), (8347444, 'bl loc.imp.objc_msgSend'), (8347464, 'bl loc.imp.objc_msgSend'), (8347476, 'bl sym.imp.__wrap_malloc'), (8347564, 'bl loc.imp.objc_msgSend'), (8347596, 'blx r3'), (8347628, 'blx lr'), (8347644, 'blx r2'), (8347656, 'bl sym.imp.__wrap_free'), (8347744, 'blx r2'), (8347804, 'blx r2'), (8347900, 'blx ip'), (8348000, 'blx ip'), (8348104, 'blx ip'), (8348224, 'blx ip'), (8348328, 'blx r3')],
        branches=[(8337716, 'beq', 8348332), (8338200, 'bne', 8338320), (8338404, 'beq', 8338476), (8338512, 'beq', 8338820), (8338956, 'beq', 8339492), (8339280, 'beq', 8339488), (8339488, 'b', 8340280), (8339528, 'beq', 8339736), (8339828, 'beq', 8340040), (8339964, 'beq', 8339984), (8339984, 'b', 8340196), (8340172, 'beq', 8340192), (8340192, 'b', 8340196), (8340380, 'beq', 8340536), (8340548, 'bne', 8340640), (8340652, 'bne', 8340932), (8340668, 'beq', 8340824), (8340836, 'bne', 8340928), (8340928, 'b', 8340932), (8340944, 'beq', 8344536), (8341216, 'beq', 8344500), (8341296, 'beq', 8341308), (8341504, 'blo', 8342628), (8341624, 'bpl', 8341832), (8341788, 'b', 8342292), (8341884, 'bmi', 8341944), (8341940, 'bpl', 8342128), (8342104, 'b', 8342288), (8342288, 'b', 8342292), (8342612, 'b', 8343484), (8342768, 'bpl', 8342968), (8342932, 'b', 8343432), (8343020, 'bmi', 8343080), (8343076, 'bpl', 8343268), (8343240, 'b', 8343428), (8343428, 'b', 8343432), (8344016, 'bls', 8344184), (8344084, 'bne', 8344184), (8344172, 'b', 8344368), (8344192, 'ble', 8344288), (8344280, 'b', 8344364), (8344364, 'b', 8344368), (8344404, 'blo', 8341260), (8344496, 'bne', 8341260), (8344500, 'b', 8344504), (8344504, 'b', 8348260), (8344548, 'beq', 8348256), (8344820, 'beq', 8348248), (8344900, 'beq', 8344912), (8345108, 'blo', 8346200), (8345228, 'bpl', 8345412), (8345392, 'b', 8345856), (8345464, 'bmi', 8345524), (8345520, 'bpl', 8345692), (8345684, 'b', 8345852), (8345852, 'b', 8345856), (8346176, 'b', 8347028), (8346340, 'bpl', 8346508), (8346504, 'b', 8346976), (8346560, 'bmi', 8346620), (8346616, 'bpl', 8346812), (8346780, 'b', 8346972), (8346972, 'b', 8346976), (8347752, 'bls', 8347912), (8347820, 'bne', 8347912), (8347908, 'b', 8348116), (8347920, 'ble', 8348036), (8348008, 'b', 8348112), (8348112, 'b', 8348116), (8348152, 'blo', 8344864), (8348244, 'bne', 8344864), (8348248, 'b', 8348252), (8348252, 'b', 8348256), (8348256, 'b', 8348260)],
        semantics=('LoadWorldUI -[currentWorldChanged:] @0x007f36d0 (2843 words, 74 branches, 130 calls; [census] grade): rebuilds the whole world card for the newly selected save. Types v12@0:4@8; frame push {r4-r8,sl,fp,lr}, sub sp,#0x750. (A) Preamble 0x7f36d0-0x7f3960: caches ivar-offset cells (gameSave@36, hostPicButton@112, onlinePicButton@132, picTexture@148, hostUserPhoto@156, blockheadPreviews@32, state@40, windowInfo@8, cache@12, playButton@20, optionsButton@24, disabledTextView@56, blockheadNamesTextView@28) and the SELs autorelease/retain/release/setGlyphTexture:, then runs 7 autorelease sends (0x7f37c8..0x7f3948, ARC teardown of the previous world: gameSave first) and clears the ivars. (B) Avatar texture 0x7f395c-0x7f3dc0: NSSearchPathForDirectoriesInDomains (2x, sym.imp) -> NSFileManager defaultManager + fileExistsAtPath: (2x) -> stringByAppendingPathComponent: chains with @"%@/saves/%@/avatar_%@_.png" (struct 0x00f918b8, keys playerID 0x00f918d8 / saveID 0x00f918c8) and @"avatar.png" (0x00f918e8) -> [UIImage imageWithContentsOfFile:] -> retain -> [[CPTexture2D alloc] initWithUIImage:] -> [texture setGlyphTexture:...]; results land in picTexture@148 and drive hostPicButton@112 / onlinePicButton@132 / hostUserPhoto@156. (C) Titles 0x7f3e20-0x7f4338: builds the header from [gameSave objectForKey:...] - @"remoteGame" (0x00f918f8), @"userName" (0x00f91918) + @"JOIN" (0x00f91928) form @"ONLINE WORLD - %@\\n" (0x00f91908); otherwise @"customRulesDict" (0x00f91938) and @"expertMode" (0x00f91958) boolValue pick between "OFFLINE WORLD - SURVIVAL\\n" (0x00f91978) / "OFFLINE WORLD - EXPERT SURVIVAL\\n" (0x00f91988) / "OFFLINE WORLD - CUSTOM RULES\\n" (0x00f91948) / "OFFLINE WORLD - EXPERT CUSTOM RULES\\n" (0x00f91968) (stringWithFormat:/stringByAppendingFormat:), and ends with [self->playButton setTitle:@"PLAY" (0x00f91808)] (SEL setTitle: 0x007f4da8). (D) Blockhead data 0x7f4338-0x7f45c4: pid = [gameSave objectForKey:@"playerID"]; then key = [NSString stringWithFormat:@"%@_blockheadDatasv2" (0x00f91998), pid] -> X = [gameSave objectForKey:key] (fallback key @"blockheadDatasv2" 0x00f919a8); a second fallback path builds @"%@_blockheadDatas" (0x00f919b8) / @"blockheadDatas" (0x00f919c8) into Y. (E) Branch X != nil 0x7f45d0-0x7f53b4: self->blockheadPreviews@32 = [[NSMutableArray alloc] init] (0x7f4670); fast-enumeration for-in over X (countByEnumeratingWithState:objects:count: SEL 0x007f53cc, memset of the 0x20-byte state at 0x7f46a4, objc_enumerationMutation x2 = two loops): per element it builds BlockheadPreviewView instances (alloc + initWithFrame:cache:windowInfo: with rects from the 0x7ed878 packer x12 + setFrame:), fills them with setFromPreviewData: / setWalking: / setHidden:, splits the per-blockhead blob with [obj length] -> __wrap_malloc -> getBytes:range: -> [[NSString alloc] initWithBytes:length:encoding:] -> autorelease -> __wrap_free, and appends names via stringByAppendingFormat: with @"%@& %@", @",%@%@", @"%@" (structs 0x00f919f8/0x00f91a08/0x00f91a18) and "\\n"/" " separators. Preview y/positions come from windowInfo@8 float compares (vcmpe.f32 + bpl/bmi) as in the other bodies. (F) Branch X == nil 0x7f53d8-0x7f6254: same-shaped rebuild from Y (the second, byte-copy of the string table at 0x00f919d8-0x00f91a08 is reused), including a call to the internal struct-filler helper at 0x007f633c (bl at 0x7f5ec0; it writes shorts at +0x14..+0x22 and bytes at +0x24/+0x25 into the record handed in r0). (G) Tail 0x7f6264: [self->blockheadNamesTextView@28 setString:<assembled names>] (SEL setString: cell 0x007f6334), epilogue. Call histogram: 12 bl 0x7ed878 (rect packer), 1 bl 0x7f633c (struct filler), 10 bl loc.imp.objc_msgSend, 2 bl sym.imp.NSSearchPathForDirectoriesInDomains, 2 memset, 2 objc_enumerationMutation, 1 __aeabi_memcpy, 2 __wrap_malloc, 2 __wrap_free, 88 blx rN (r3 33, ip 27, r2 18, lr 10, r4 5, r5 2, r8 1). Branches: 29 b (tail trampolines/joins), 17 beq, 8 bne, 8 bpl + 4 bmi (layout float switches), 4 blo (bounds), 2 bls + 2 ble (preview-count compares).'),
    ),
    dict(
        name='lwu_06',
        method='LoadWorldUI -[dealloc]',
        types='v8@0:4',
        start=8313692,
        end=8315136,
        disasm='disasm_worldtileloader_lwu_06.txt',
        base_add=8313708,
        base_literal=8315132,
        boundary='ARM.exidx end 0x007ee100 (listing bound); next ObjC IMP 0x007ee100 LoadWorldUI -[windowInfoChanged:]',
        selectors={
                 0x7ee088: (15211200, 'dealloc'),
                 0x7ee094: (15211196, 'release'),
                 0x7ee0d4: (15211188, 'autorelease'),
                 0x7ee0f8: (15211192, 'dismissAlertViews'),
        },
        imports={
                 0x7ee084: (17151900, 'objc_msgSendSuper2'),
                 0x7ee090: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7ee098: (17160924, 'OBJC_IVAR_$_LoadWorldUI.hostUserName', 152),
                 0x7ee09c: (17160940, 'OBJC_IVAR_$_LoadWorldUI.hostNowButton', 124),
                 0x7ee0a0: (17160944, 'OBJC_IVAR_$_LoadWorldUI.hostPvpButton', 120),
                 0x7ee0a4: (17160948, 'OBJC_IVAR_$_LoadWorldUI.hostPvpTitleTextView', 116),
                 0x7ee0a8: (17160952, 'OBJC_IVAR_$_LoadWorldUI.hostPicButton', 112),
                 0x7ee0ac: (17160956, 'OBJC_IVAR_$_LoadWorldUI.hostPicTextView', 108),
                 0x7ee0b0: (17160960, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameButton', 104),
                 0x7ee0b4: (17160964, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameTitleTextView', 100),
                 0x7ee0b8: (17160968, 'OBJC_IVAR_$_LoadWorldUI.hostMultiLANButton', 96),
                 0x7ee0bc: (17160972, 'OBJC_IVAR_$_LoadWorldUI.migrateToCustomButton', 92),
                 0x7ee0c0: (17160976, 'OBJC_IVAR_$_LoadWorldUI.hostMultiButton', 88),
                 0x7ee0c4: (17160980, 'OBJC_IVAR_$_LoadWorldUI.worldNameButton', 84),
                 0x7ee0c8: (17160984, 'OBJC_IVAR_$_LoadWorldUI.worldNameTextView', 80),
                 0x7ee0cc: (17160988, 'OBJC_IVAR_$_LoadWorldUI.deleteWorldButton', 52),
                 0x7ee0d0: (17160992, 'OBJC_IVAR_$_LoadWorldUI.backButton', 48),
                 0x7ee0d8: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
                 0x7ee0dc: (17161000, 'OBJC_IVAR_$_LoadWorldUI.picTexture', 148),
                 0x7ee0e0: (17161004, 'OBJC_IVAR_$_LoadWorldUI.hostUserPhoto', 156),
                 0x7ee0e4: (17160916, 'OBJC_IVAR_$_LoadWorldUI.optionsButton', 24),
                 0x7ee0e8: (17160912, 'OBJC_IVAR_$_LoadWorldUI.playButton', 20),
                 0x7ee0ec: (17160920, 'OBJC_IVAR_$_LoadWorldUI.disabledTextView', 56),
                 0x7ee0f0: (17160908, 'OBJC_IVAR_$_LoadWorldUI.blockheadNamesTextView', 28),
                 0x7ee0f4: (17161008, 'OBJC_IVAR_$_LoadWorldUI.blockheadPreviews', 32),
        },
        classes={
                 0x7ee08c: (15252832, 'OBJC_CLASS_$_LoadWorldUI'),
        },
        instructions=[(8313692, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8315132, 'addeq r1, r7, r0, lsl 31')],
        calls=[(8314120, 'blx r6'), (8314156, 'blx r3'), (8314192, 'blx r3'), (8314228, 'blx r3'), (8314264, 'blx r3'), (8314300, 'blx r3'), (8314336, 'blx r3'), (8314372, 'blx r3'), (8314408, 'blx r3'), (8314456, 'blx ip'), (8314492, 'blx r3'), (8314528, 'blx r3'), (8314564, 'blx r3'), (8314600, 'blx r3'), (8314636, 'blx r3'), (8314672, 'blx r3'), (8314708, 'blx r3'), (8314744, 'blx r3'), (8314780, 'blx r3'), (8314816, 'blx r3'), (8314852, 'blx r3'), (8314888, 'blx r3'), (8314924, 'blx r3'), (8314960, 'blx r3'), (8315000, 'blx r2')],
        branches=[],
        semantics=('LoadWorldUI -[dealloc] @0x007edb5c (361 words, 25 calls, 0 branches; census-lite) - straight-line ARC/Apportable destructor, no conditionals at all. PIC base 0x0105faf4 (pool cell 0x007ee0fc = 0x871f80 + pc 0x007edb6c). Head 0x007edb68..0x007edcdc pre-loads every constant it needs (23 OBJC_IVAR offset cells + SEL release / SEL autorelease / SEL dismissAlertViews / SEL dealloc / CLASS LoadWorldUI / objc_msgSend / objc_msgSendSuper2) and spills them into a descending stack-slot table ([sp,0x2c]..[sp,0x58], [fp,-0x30]..[fp,-0x54], [sp,0x20]/[sp,0x24]); the sends then walk that table in the reverse of the load order. Send 1 (0x007edd08, msgSend from r6): [self dismissAlertViews] (SEL cell 0x007ee0f8 -> 0x00e81fc4) - this is why the alert-view ivars (60..76) are not touched below. Sends 2-24 (0x007edd2c..0x007ee050): one \'-release\' per object ivar, in the order blockheadPreviews@32, blockheadNamesTextView@28, disabledTextView@56, playButton@20, optionsButton@24, hostUserPhoto@156, picTexture@148, gameSave@36, backButton@48, deleteWorldButton@52, worldNameTextView@80, worldNameButton@84, hostMultiButton@88, migrateToCustomButton@92, hostMultiLANButton@96, hostNickNameTitleTextView@100, hostNickNameButton@104, hostPicTextView@108, hostPicButton@112, hostPvpTitleTextView@116, hostPvpButton@120, hostNowButton@124, hostUserName@152. The gameSave@36 slot is the single exception: its cell (0x007ee0d8 -> GOT 0x0105db24) is paired with SEL autorelease (cell 0x007ee0d4 -> selref 0x00e81fc0) so the call at 0x007ede28 is [self->gameSave autorelease], not release. Send 25 (0x007ee078, blx via msgSendSuper2 from [sp,0x18]): [super dealloc] - the super struct lives at fp-0x28 and is built at 0x007ee054..0x007ee064 as {self, OBJC_CLASS_$_LoadWorldUI (cell 0x007ee08c)} with SEL dealloc (cell 0x007ee088, selref 0x00e81fcc). Epilogue \'sub sp,fp,#0x18; pop {r4,r5,r6,r7,r8,sl,fp,pc}\'.'),
    ),
    dict(
        name='lwu_07',
        method='LoadWorldUI -[deleteWorldButton:]',
        types='v12@0:4@8',
        start=8382188,
        end=8384120,
        disasm='disasm_worldtileloader_lwu_07.txt',
        base_add=8382204,
        base_literal=8384116,
        boundary='ARM.exidx end 0x007fee78 (listing bound); next ObjC IMP 0x007ff328 LoadWorldUI -[hostMultiButton:]',
        selectors={
                 0x7fee04: (15211372, 'setDestructiveButtonWithTitle:block:'),
                 0x7fee08: (17113072, 'ELF'),
                 0x7fee1c: (15211364, 'setCancelButtonWithTitle:block:'),
                 0x7fee20: (17113040, 'ELF'),
                 0x7fee2c: (15211360, 'initWithTitle:message:'),
                 0x7fee30: (15211348, 'uppercaseString'),
                 0x7fee34: (15211120, 'alloc'),
                 0x7fee40: (15211228, 'stringWithFormat:'),
                 0x7fee48: (15211224, 'objectForKey:'),
                 0x7fee58: (17113008, 'ELF'),
                 0x7fee60: (17112976, 'ELF'),
                 0x7fee70: (15211376, 'show'),
        },
        imports={
                 0x7fedfc: (16325480, '__CFConstantStringClassReference'),
                 0x7fee00: (17151904, 'objc_msgSend'),
                 0x7fee14: (17151928, '_NSConcreteStackBlock'),
                 0x7fee18: (16325416, '__CFConstantStringClassReference'),
                 0x7fee28: (16325464, '__CFConstantStringClassReference'),
                 0x7fee3c: (16325448, '__CFConstantStringClassReference'),
                 0x7fee44: (16325336, '__CFConstantStringClassReference'),
                 0x7fee54: (16325432, '__CFConstantStringClassReference'),
                 0x7fee68: (16325400, '__CFConstantStringClassReference'),
                 0x7fee6c: (16325384, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7fedf4: (17160936, 'OBJC_IVAR_$_LoadWorldUI.deleteAlertView', 60),
                 0x7fedf8: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x7fee4c: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
        },
        classes={
                 0x7fee38: (15247272, 'OBJC_CLASS_$_BlockAlertView'),
                 0x7fee50: (15247248, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(8382188, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8384116, 'strdeq r1, r2, [r6], r0')],
        calls=[(8382736, 'blx r3'), (8382752, 'blx r2'), (8382788, 'blx ip'), (8382824, 'blx r3'), (8382856, 'blx r3'), (8382892, 'blx ip'), (8383004, 'blx r5'), (8383100, 'blx r5'), (8383548, 'blx r3'), (8383564, 'blx r2'), (8383600, 'blx ip'), (8383636, 'blx r3'), (8383668, 'blx r3'), (8383704, 'blx ip'), (8383816, 'blx r5'), (8383912, 'blx r5'), (8383976, 'blx r2')],
        branches=[(8382256, 'bne', 8383980), (8382292, 'bne', 8383108), (8383104, 'b', 8383916)],
        semantics=('LoadWorldUI -[deleteWorldButton:] @0x007fe6ec (483 words, 3 branches, 17 calls; [census-lite]): one-shot guard + two near-identical BlockAlertView confirmation builders. Guard (0x007fe718..0x007fe730): if self->deleteAlertView@60 (.got 0x0105dae8) != nil -> bne straight to the epilogue 0x007fedec, so at most one delete dialog exists at a time. Then self->state@40 (.got 0x0105dabc) is compared with 1 (0x007fe750): state == 1 takes the SINGLE-PLAYER variant (0x007fe758..0x007fea80), anything else the SERVER variant (0x007fea84..), and both reach the shared tail 0x007fedac that ends with CALL16 0x007fede8 objc_msgSend(self->deleteAlertView, @selector(show)) (selref 0x00e81b70). SINGLE-PLAYER: CALL0 0x007fe910 = objc_msgSend(self->gameSave@36 (.got 0x0105db24), @selector(objectForKey:) (selref 0x00e81ad8), @"worldName" (CFString 0x00f91ad8)); CALL1 0x007fe920 = [worldName uppercaseString]; CALL2 0x007fe944 = [NSString (classref 0x00e8a790) stringWithFormat: @"Are you sure you want to delete the world %@?\\n\\nThis is a single player world so if you delete it from this device it will be gone for good. You cannot get it back again!" (CFString 0x00f91b08), UPPER(worldName)]; CALL3 0x007fe968 = [BlockAlertView (classref 0x00e8a7a8) alloc]; CALL4 0x007fe988 = [message uppercaseString] - the already-formatted message is uppercased a second time (verified in the raw listing: r0 <- [fp,-0x2c] = the CALL2 result); CALL5 0x007fe9ac = [alertView initWithTitle:@"DELETE WORLD?" (0x00f91b18) message:UPPER(message)]; the object is stored into deleteAlertView@60 by the inline \'str r0,[self+60]\' at 0x007fe9c0. Two 6-word stack block literals are then written: CANCEL at fp-0x48 (isa = _NSConcreteStackBlock import 0x0105b7b8, flags 0xC2000000 from pool cell 0x007fee10, reserved 0, invoke 0x007fee78, descriptor 0x01051f90 = {0, 0x18, copy 0x007fef14, dispose 0x007fef54}, captured self at fp-0x34) and DELETE at fp-0x60 (invoke 0x007fef7c, descriptor 0x01051fb0); CALL6 0x007fea1c = [alertView setCancelButtonWithTitle:@"CANCEL" (0x00f91b28) block:block(fp-0x48)] and CALL7 0x007fea7c = [alertView setDestructiveButtonWithTitle:@"DELETE" (0x00f91b38) block:block(fp-0x60)] (selrefs 0x00e81b64 / 0x00e81b6c). SERVER variant repeats the recipe with @"FORGET WORLD?" (0x00f91b58), @"FORGET" (0x00f91b68) and the message @"Are you sure you want to forget the world %@?\\n\\nThis is a server world, so you may still be able to re-join this server with the same username and retrieve your progress later." (0x00f91b48): CALL8 0x007fec3c objectForKey:@"worldName", CALL9 0x007fec4c [worldName uppercaseString], CALL10 0x007fec70 stringWithFormat:, CALL11 0x007fec94 [BlockAlertView alloc], CALL12 0x007fecb4 [message uppercaseString], CALL13 0x007fecd8 [alertView initWithTitle:@"FORGET WORLD?" message:UPPER(message)] stored into deleteAlertView@60 at 0x007fecec, then CALL14 0x007fed48 setCancelButtonWithTitle:@"CANCEL" block: (block at fp-0x80, invoke 0x007ff0d0, descriptor 0x01051fd0) and CALL15 0x007feda8 setDestructiveButtonWithTitle:@"FORGET" block: (block at fp-0x98, invoke 0x007ff1d4, descriptor 0x01051ff0). Both variants pass through the spilt-constant idiom (r4..sl written to the stack around each send). The button argument (r2 -> [fp,-0x28]) is dead. Frame push {r4,r5,r6,r7,r8,sl,fp,lr}/sub sp,#0x198.'),
    ),
    dict(
        name='lwu_08',
        method='LoadWorldUI -[dismissAlertViews]',
        types='v8@0:4',
        start=8313172,
        end=8313692,
        disasm='disasm_worldtileloader_lwu_08.txt',
        base_add=8313188,
        base_literal=8313688,
        boundary='ARM.exidx end 0x007edb5c (listing bound); next ObjC IMP 0x007edb5c LoadWorldUI -[dealloc]',
        selectors={
                 0x7edb48: (15211188, 'autorelease'),
                 0x7edb4c: (15211184, 'dismissWithClickedButtonIndex:animated:'),
        },
        imports={
                 0x7edb44: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7edb40: (17160928, 'OBJC_IVAR_$_LoadWorldUI.portalAlertView', 72),
                 0x7edb50: (17160932, 'OBJC_IVAR_$_LoadWorldUI.shareAlertView', 68),
                 0x7edb54: (17160936, 'OBJC_IVAR_$_LoadWorldUI.deleteAlertView', 60),
        },
        classes={},
        instructions=[(8313172, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8313688, 'addeq r2, r7, r8, lsl 3')],
        calls=[(8313348, 'blx lr'), (8313384, 'blx r3'), (8313468, 'blx r5'), (8313504, 'blx r3'), (8313588, 'blx r5'), (8313624, 'blx r3')],
        branches=[],
        semantics=('LoadWorldUI -[dismissAlertViews] @0x007ed954 (130 words, 0 branches, 6 calls): tears down three alert views in the order deleteAlertView@60, shareAlertView@68, portalAlertView@72. Entry hoists the constants: r4 = objc_msgSend (.got 0x0105b7a0), r5 = selref @selector(autorelease) (0x00e81ab4), r6 = -1 (mvn r6,0), r7 = 0, r8 = selref @selector(dismissWithClickedButtonIndex:animated:) (0x00e81ab0), sl = &OBJC_IVAR_$_LoadWorldUI.shareAlertView (.got 0x0105dae4), ip = &OBJC_IVAR_$_LoadWorldUI.portalAlertView (.got 0x0105dae0), r0 = &OBJC_IVAR_$_LoadWorldUI.deleteAlertView (.got 0x0105dae8); self is parked at [fp,-0x1c]. Each of the three blocks uses the identical Apportable ARC teardown triple: (1) objc_msgSend(self-><alert>, @selector(dismissWithClickedButtonIndex:animated:), -1, (sxtb)0) - CALL0 0x007eda04 delete, CALL2 0x007eda7c share, CALL4 0x007edaf4 portal; (2) objc_msgSend(self-><alert>, @selector(autorelease)) - CALL1/CALL3/CALL5 (0x007eda28/0x007eda9c/0x007edb18), the release of the old value; (3) a plain \'store 0\' into the slot: add rX,self,[ivar-var]; str #0,[rX] (0x007eda40/0x007edab8/0x007edb30) - no dmb and no objc_storeStrong call, i.e. the inline strong-store-nil form. textEntryAlertView@64 and shareTextAlertView@76 are NOT touched by this method. Zero branch instructions; registers r4..sl are spilled to [sp,0x10..0x2c] around the sends; epilogue sub sp,fp,#0x18.'),
    ),
    dict(
        name='lwu_09',
        method='LoadWorldUI -[endTouch:]',
        types='v16@0:4{CGPoint=ff}8',
        start=8408184,
        end=8409792,
        disasm='disasm_worldtileloader_lwu_09.txt',
        base_add=8408200,
        base_literal=8409788,
        boundary='ARM.exidx end 0x008052c0 (listing bound); next ObjC IMP 0x008052c0 LoadWorldUI -[textField:shouldChangeCharactersInRange:replacementString:]',
        selectors={
                 0x805270: (15211420, 'endTouch:'),
        },
        imports={},
        ivars={
                 0x805264: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x805268: (17160992, 'OBJC_IVAR_$_LoadWorldUI.backButton', 48),
                 0x805274: (17160960, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameButton', 104),
                 0x805278: (17160952, 'OBJC_IVAR_$_LoadWorldUI.hostPicButton', 112),
                 0x80527c: (17160944, 'OBJC_IVAR_$_LoadWorldUI.hostPvpButton', 120),
                 0x805280: (17160940, 'OBJC_IVAR_$_LoadWorldUI.hostNowButton', 124),
                 0x805288: (17160968, 'OBJC_IVAR_$_LoadWorldUI.hostMultiLANButton', 96),
                 0x805290: (17160988, 'OBJC_IVAR_$_LoadWorldUI.deleteWorldButton', 52),
                 0x805294: (17161020, 'OBJC_IVAR_$_LoadWorldUI.onlinePicButton', 132),
                 0x805298: (17161024, 'OBJC_IVAR_$_LoadWorldUI.onlineShareButton', 136),
                 0x80529c: (17161028, 'OBJC_IVAR_$_LoadWorldUI.onlineOwnerPortalButton', 140),
                 0x8052a4: (17160980, 'OBJC_IVAR_$_LoadWorldUI.worldNameButton', 84),
                 0x8052a8: (17160976, 'OBJC_IVAR_$_LoadWorldUI.hostMultiButton', 88),
                 0x8052ac: (17160972, 'OBJC_IVAR_$_LoadWorldUI.migrateToCustomButton', 92),
                 0x8052b0: (17160912, 'OBJC_IVAR_$_LoadWorldUI.playButton', 20),
                 0x8052b8: (17160916, 'OBJC_IVAR_$_LoadWorldUI.optionsButton', 24),
        },
        classes={},
        instructions=[(8408184, 'push {fp, lr}'), (8409788, 'addeq sl, r5, r4, ror 28')],
        calls=[(8408336, 'bl loc.imp.objc_msgSend'), (8408396, 'bl loc.imp.objc_msgSend'), (8408520, 'bl loc.imp.objc_msgSend'), (8408580, 'bl loc.imp.objc_msgSend'), (8408640, 'bl loc.imp.objc_msgSend'), (8408700, 'bl loc.imp.objc_msgSend'), (8408760, 'bl loc.imp.objc_msgSend'), (8408884, 'bl loc.imp.objc_msgSend'), (8408944, 'bl loc.imp.objc_msgSend'), (8409004, 'bl loc.imp.objc_msgSend'), (8409064, 'bl loc.imp.objc_msgSend'), (8409124, 'bl loc.imp.objc_msgSend'), (8409248, 'bl loc.imp.objc_msgSend'), (8409308, 'bl loc.imp.objc_msgSend'), (8409432, 'bl loc.imp.objc_msgSend'), (8409492, 'bl loc.imp.objc_msgSend'), (8409552, 'bl loc.imp.objc_msgSend'), (8409612, 'bl loc.imp.objc_msgSend'), (8409672, 'bl loc.imp.objc_msgSend')],
        branches=[(8408252, 'bne', 8408404), (8408400, 'b', 8409692), (8408436, 'bne', 8408768), (8408764, 'b', 8409688), (8408800, 'bne', 8409132), (8409128, 'b', 8409684), (8409164, 'bne', 8409316), (8409312, 'b', 8409680), (8409348, 'bne', 8409676), (8409676, 'b', 8409680), (8409680, 'b', 8409684), (8409684, 'b', 8409688), (8409688, 'b', 8409692)],
        semantics=('LoadWorldUI -[endTouch:] @@0x00804c78 (402 words, 13 branches, 19 calls; [census-lite]): state-machine touch router. Reads OBJC_IVAR_$_LoadWorldUI.state@40 (cell 0x00805264) and forwards the CGPoint argument ((x,y) = (r2,r3) spilled to [fp,-8]/[fp,-4]) with @selector(endTouch:) (SEL cell 0x00805270) to the buttons of the current page only - one bl loc.imp.objc_msgSend per ivar, each receiver addressed through its own offset cell: state 0: playButton@20 (cell 0x008052b0), optionsButton@24 (0x008052b8); state 1: backButton@48 (0x00805268), deleteWorldButton@52 (0x00805290), worldNameButton@84 (0x008052a4), hostMultiButton@88 (0x008052a8), migrateToCustomButton@92 (0x008052ac); state 2: backButton@48, deleteWorldButton@52, onlinePicButton@132 (0x00805294), onlineShareButton@136 (0x00805298), onlineOwnerPortalButton@140 (0x0080529c); state 3: backButton@48, hostMultiLANButton@96 (0x00805288); state 4: backButton@48, hostNickNameButton@104 (0x00805274), hostPicButton@112 (0x00805278), hostPvpButton@120 (0x0080527c), hostNowButton@124 (0x00805280). Any other state value falls through the bne chain to the epilogue (no sends). All sends are to possibly-nil ivars (safe no-ops when the button is absent). Base T=pc+0x85ae64=0x0105faf4. Instruction stream is identical to lwu_23 (moveTouch:) apart from SEL/pool constants (382 vs 381 parsed rows, diff only at the literal-pool tail).'),
    ),
    dict(
        name='lwu_10',
        method='LoadWorldUI -[hostMultiButton:]',
        types='v12@0:4@8',
        start=8385320,
        end=8386768,
        disasm='disasm_worldtileloader_lwu_10.txt',
        base_add=8385336,
        base_literal=8386764,
        boundary='ARM.exidx end 0x007ff8d0 (listing bound); next ObjC IMP 0x007ff8d0 LoadWorldUI -[migrateToCustomButton:]',
        selectors={
                 0x7ff88c: (15211120, 'alloc'),
                 0x7ff89c: (15211152, 'setTarget:action:'),
                 0x7ff8a0: (15211380, 'hostMultiLANButton:'),
                 0x7ff8a4: (15211144, 'setBackgroundSelectedTexture:'),
                 0x7ff8ac: (15211136, 'textureNamed:'),
                 0x7ff8b4: (15211140, 'setBackgroundTexture:'),
                 0x7ff8c8: (15211132, 'initWithFrame:cache:windowInfo:title:'),
        },
        imports={
                 0x7ff888: (17151904, 'objc_msgSend'),
                 0x7ff8a8: (16324696, '__CFConstantStringClassReference'),
                 0x7ff8b8: (16324680, '__CFConstantStringClassReference'),
                 0x7ff8bc: (16325496, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7ff878: (17160968, 'OBJC_IVAR_$_LoadWorldUI.hostMultiLANButton', 96),
                 0x7ff87c: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x7ff884: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7ff8b0: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
        },
        classes={
                 0x7ff890: (15247240, 'OBJC_CLASS_$_MJButton'),
        },
        instructions=[(8385320, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8386764, 'strheq r0, [r6], r4')],
        calls=[(8385492, 'blx r3'), (8385800, 'bl 0x7ed878'), (8386020, 'bl 0x7ed878'), (8386392, 'bl loc.imp.objc_msgSend'), (8386480, 'blx lr'), (8386512, 'blx r3'), (8386580, 'blx lr'), (8386612, 'blx r3'), (8386660, 'blx lr')],
        branches=[(8385416, 'bne', 8386664), (8385536, 'bpl', 8385808), (8385592, 'bpl', 8385652), (8385648, 'b', 8385672), (8385668, 'b', 8385672), (8385804, 'b', 8386024), (8385860, 'bpl', 8385928), (8385916, 'b', 8385948), (8385944, 'b', 8385948)],
        semantics=('LoadWorldUI -[hostMultiButton:] @0x007ff328 (362 words, 9 branches, 9 calls; [census-lite]): first-tap lazily creates the "HOST LOCAL NETWORK..." button. Entry: self->state@40 = 3 (movw 3 via the state cell 0x007ff87c), then the guard - if self->hostMultiLANButton@96 != nil (cell 0x007ff878) it branches to the epilogue, so all layout work happens only once. Frame: the internal CGRect packer at 0x007ed878 (out=r0; x=r1, y=r2, w=r3, h=[sp]) is called twice (0x007ff508 / 0x007ff5e4) with x=-113.0f (0xc2e20000), w=226.0f (0x43620000), h=40.0f (0x42200000), writing to [fp-0x38]; y is chosen by float switches on windowInfo->f4 (windowInfo@8) against 415.0 (0x007ff580/0x007ff880) and 160.0 (0x007ff584): short window -> y=0.0 (0x007ff870), mid -> y=winC-160.0, then y = y - winInfo->f0xc + 1.0 + 48.0 + 48.0 (0x007ff874=48.0) and packer#1; tall (>=415.0) -> y=0.0 + 4.0 and packer#2. The 0x007ff548..0x007ff57c arm (y=winC-160.0 on the tall path) is dead code - path A re-tests the very same >=415.0 condition that selected it. Then 6 sends: [[MJButton alloc] initWithFrame:<packer rect> cache:self->cache@12 windowInfo:self->windowInfo@8 title:@"HOST LOCAL NETWORK..." (0xf91b78, cell 0x007ff8bc)] (frame = r2/r3/[sp]/[sp+4], then cache, windowInfo, title on the stack; bl loc.imp.objc_msgSend at 0x007ff758) -> result stored to self->hostMultiLANButton@96; [self->cache textureNamed:@"InventoryButtonBackground.png" (0xf91848, cell 0x7ff8b8)] -> [button setBackgroundTexture:]; [self->cache textureNamed:@"InventoryButtonBackgroundSelected.png" (0xf91858, cell 0x007ff8a8)] -> [button setBackgroundSelectedTexture:]; [button setTarget:self action:@selector(hostMultiLANButton:) (cell 0x007ff8a0)]. SEL cells: alloc 0x007ff88c, setTarget:action: 0x007ff89c, textureNamed: 0x007ff8ac, setBackgroundTexture: 0x007ff8b4, setBackgroundSelectedTexture: 0x007ff8a4, initWithFrame:cache:windowInfo:title: 0x007ff8c8. Base T=pc+0x8607b4=0x0105faf4.'),
    ),
    dict(
        name='lwu_11',
        method='LoadWorldUI -[hostMultiLANButton:]',
        types='v12@0:4@8',
        start=8388424,
        end=8403956,
        disasm='disasm_worldtileloader_lwu_11.txt',
        base_add=8388440,
        base_literal=8392372,
        boundary='ARM.exidx end 0x00803bf4 (listing bound); next ObjC IMP 0x00803bf4 LoadWorldUI -[startTouch:]',
        selectors={
                 0x800f90: (15211120, 'alloc'),
                 0x8013a4: (15211124, 'standardFont'),
                 0x8013a8: (15211128, 'initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:'),
                 0x801454: (15211216, 'setString:'),
                 0x801828: (15211212, 'setFrame:'),
                 0x801c2c: (15211344, 'setTitleAlignment:'),
                 0x801c38: (15211152, 'setTarget:action:'),
                 0x801c3c: (15211388, 'hostNickNameButton:'),
                 0x801c40: (15211220, 'setGlyphTexture:'),
                 0x801c48: (15211136, 'textureNamed:'),
                 0x801cec: (15211152, 'setTarget:action:'),
                 0x801cf0: (15211220, 'setGlyphTexture:'),
                 0x801cf4: (15211136, 'textureNamed:'),
                 0x801d54: (15211348, 'uppercaseString'),
                 0x801d58: (15211132, 'initWithFrame:cache:windowInfo:title:'),
                 0x801dcc: (15211132, 'initWithFrame:cache:windowInfo:title:'),
                 0x802e58: (15211144, 'setBackgroundSelectedTexture:'),
                 0x802e60: (15211140, 'setBackgroundTexture:'),
                 0x80316c: (15211392, 'hostPicButton:'),
                 0x80352c: (15211120, 'alloc'),
                 0x8037f8: (15211124, 'standardFont'),
                 0x8038c0: (15211128, 'initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:'),
                 0x803b5c: (15211212, 'setFrame:'),
                 0x803b6c: (15211120, 'alloc'),
                 0x803b84: (15211212, 'setFrame:'),
                 0x803b8c: (15211152, 'setTarget:action:'),
                 0x803b90: (15211136, 'textureNamed:'),
                 0x803b94: (15211132, 'initWithFrame:cache:windowInfo:title:'),
                 0x803b98: (15211144, 'setBackgroundSelectedTexture:'),
                 0x803b9c: (15211140, 'setBackgroundTexture:'),
                 0x803bb0: (15211396, 'boolForKey:'),
                 0x803bb4: (15211160, 'standardUserDefaults'),
                 0x803bbc: (15211404, 'setOn:'),
                 0x803bc0: (15211400, 'hostPvpButton:'),
                 0x803bc8: (15211268, 'initWithFrame:cache:windowInfo:'),
                 0x803bd8: (15211408, 'hostNowButton:'),
        },
        imports={
                 0x800f8c: (17151904, 'objc_msgSend'),
                 0x8011d4: (16324760, '__CFConstantStringClassReference'),
                 0x8011d8: (16324776, '__CFConstantStringClassReference'),
                 0x801398: (16324760, '__CFConstantStringClassReference'),
                 0x80139c: (16324776, '__CFConstantStringClassReference'),
                 0x801c44: (16325352, '__CFConstantStringClassReference'),
                 0x8026e8: (16325544, '__CFConstantStringClassReference'),
                 0x802e5c: (16324696, '__CFConstantStringClassReference'),
                 0x802e64: (16324680, '__CFConstantStringClassReference'),
                 0x802e6c: (16324600, '__CFConstantStringClassReference'),
                 0x8030c8: (17151904, 'objc_msgSend'),
                 0x8038c4: (16325560, '__CFConstantStringClassReference'),
                 0x803b68: (17151904, 'objc_msgSend'),
                 0x803bac: (16325576, '__CFConstantStringClassReference'),
                 0x803bdc: (16324648, '__CFConstantStringClassReference'),
                 0x803be0: (16324632, '__CFConstantStringClassReference'),
                 0x803be4: (16325592, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x800eb8: (17160964, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameTitleTextView', 100),
                 0x800ebc: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x800f84: (17160964, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameTitleTextView', 100),
                 0x800f88: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x8011c4: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
                 0x801830: (17160960, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameButton', 104),
                 0x8018dc: (17160960, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameButton', 104),
                 0x801cfc: (17160924, 'OBJC_IVAR_$_LoadWorldUI.hostUserName', 152),
                 0x802204: (17160956, 'OBJC_IVAR_$_LoadWorldUI.hostPicTextView', 108),
                 0x802ac0: (17160952, 'OBJC_IVAR_$_LoadWorldUI.hostPicButton', 112),
                 0x802b30: (17160952, 'OBJC_IVAR_$_LoadWorldUI.hostPicButton', 112),
                 0x802e54: (17161000, 'OBJC_IVAR_$_LoadWorldUI.picTexture', 148),
                 0x8031c4: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x803528: (17160948, 'OBJC_IVAR_$_LoadWorldUI.hostPvpTitleTextView', 116),
                 0x8037ec: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
                 0x803b64: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x803b80: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
                 0x803ba0: (17160944, 'OBJC_IVAR_$_LoadWorldUI.hostPvpButton', 120),
                 0x803ba8: (17161032, 'OBJC_IVAR_$_LoadWorldUI.hostPvpEnabled', 160),
                 0x803bd0: (17160940, 'OBJC_IVAR_$_LoadWorldUI.hostNowButton', 124),
        },
        classes={
                 0x800f94: (15247232, 'OBJC_CLASS_$_MJTextView'),
                 0x8013a0: (15247236, 'OBJC_CLASS_$_BitmapFont'),
                 0x8018e0: (15247240, 'OBJC_CLASS_$_MJButton'),
                 0x803530: (15247232, 'OBJC_CLASS_$_MJTextView'),
                 0x8037f4: (15247236, 'OBJC_CLASS_$_BitmapFont'),
                 0x803b88: (15247240, 'OBJC_CLASS_$_MJButton'),
                 0x803ba4: (15247276, 'OBJC_CLASS_$_MJToggleButton'),
                 0x803bb8: (15247244, 'OBJC_CLASS_$_NSUserDefaults'),
        },
        instructions=[(8388424, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8403952, 'addeq fp, r5, r8, asr 31')],
        calls=[(8388596, 'blx r3'), (8389032, 'bl 0x7ed878'), (8389436, 'bl 0x7ed878'), (8389572, 'bl loc.imp.objc_msgSend'), (8389612, 'bl 0x7ed8c4'), (8389732, 'bl loc.imp.objc_msgSend'), (8389924, 'blx ip'), (8390380, 'bl 0x7ed878'), (8390776, 'bl 0x7ed878'), (8390828, 'bl loc.imp.objc_msgSend'), (8390944, 'blx r3'), (8391380, 'bl 0x7ed878'), (8391796, 'bl 0x7ed878'), (8392080, 'bl loc.imp.objc_msgSend'), (8392156, 'bl loc.imp.objc_msgSend'), (8392244, 'blx lr'), (8392276, 'blx r3'), (8392324, 'blx lr'), (8392364, 'blx r3'), (8392876, 'bl 0x7ed878'), (8393296, 'bl 0x7ed878'), (8393348, 'bl loc.imp.objc_msgSend'), (8393464, 'blx r3'), (8393916, 'bl 0x7ed878'), (8394300, 'bl 0x7ed878'), (8394396, 'bl loc.imp.objc_msgSend'), (8394436, 'bl 0x7ed8c4'), (8394568, 'bl loc.imp.objc_msgSend'), (8395092, 'bl 0x7ed878'), (8395492, 'bl 0x7ed878'), (8395544, 'bl loc.imp.objc_msgSend'), (8395660, 'blx r3'), (8396108, 'bl 0x7ed878'), (8396476, 'bl 0x7ed878'), (8396800, 'bl loc.imp.objc_msgSend'), (8396888, 'blx lr'), (8396920, 'blx r3'), (8396988, 'blx lr'), (8397020, 'blx r3'), (8397144, 'blx r3'), (8397264, 'blx r4'), (8397304, 'blx r3'), (8397752, 'bl 0x7ed878'), (8398120, 'bl 0x7ed878'), (8398236, 'bl loc.imp.objc_msgSend'), (8398292, 'blx lr'), (8398408, 'blx r3'), (8398844, 'bl 0x7ed878'), (8398896, 'bl 0x7ed878'), (8398992, 'bl loc.imp.objc_msgSend'), (8399032, 'bl 0x7ed8c4'), (8399164, 'bl loc.imp.objc_msgSend'), (8399656, 'bl 0x7ed878'), (8399712, 'bl 0x7ed878'), (8399764, 'bl loc.imp.objc_msgSend'), (8399960, 'blx r3'), (8399980, 'blx r3'), (8400056, 'blx ip'), (8400460, 'bl 0x7ed878'), (8400540, 'bl 0x7ed878'), (8400756, 'bl loc.imp.objc_msgSend'), (8400832, 'blx lr'), (8400892, 'blx lr'), (8401340, 'bl 0x7ed878'), (8401396, 'bl 0x7ed878'), (8401448, 'bl loc.imp.objc_msgSend'), (8401564, 'blx r3'), (8402516, 'bl 0x7ed878'), (8402648, 'bl loc.imp.objc_msgSend'), (8402736, 'blx lr'), (8402768, 'blx r3'), (8402836, 'blx lr'), (8402868, 'blx r3'), (8402916, 'blx lr'), (8403736, 'bl 0x7ed878'), (8403788, 'bl loc.imp.objc_msgSend')],
        branches=[(8388520, 'bne', 8389772), (8388640, 'bpl', 8389040), (8388696, 'bpl', 8388756), (8388752, 'b', 8388776), (8388772, 'b', 8388776), (8388836, 'bpl', 8388916), (8388912, 'b', 8388936), (8388932, 'b', 8388936), (8389036, 'b', 8389440), (8389092, 'bpl', 8389152), (8389148, 'b', 8389172), (8389168, 'b', 8389172), (8389232, 'bpl', 8389320), (8389308, 'b', 8389340), (8389336, 'b', 8389340), (8389756, 'b', 8390832), (8389988, 'bpl', 8390388), (8390044, 'bpl', 8390104), (8390100, 'b', 8390124), (8390120, 'b', 8390124), (8390184, 'bpl', 8390264), (8390260, 'b', 8390284), (8390280, 'b', 8390284), (8390384, 'b', 8390780), (8390440, 'bpl', 8390500), (8390496, 'b', 8390520), (8390516, 'b', 8390520), (8390580, 'bpl', 8390660), (8390656, 'b', 8390680), (8390676, 'b', 8390680), (8390868, 'bne', 8392384), (8390988, 'bpl', 8391396), (8391044, 'bpl', 8391104), (8391100, 'b', 8391124), (8391120, 'b', 8391124), (8391184, 'bpl', 8391264), (8391260, 'b', 8391284), (8391280, 'b', 8391284), (8391384, 'b', 8391800), (8391448, 'bpl', 8391508), (8391504, 'b', 8391528), (8391524, 'b', 8391528), (8391588, 'bpl', 8391680), (8391664, 'b', 8391700), (8391696, 'b', 8391700), (8392368, 'b', 8393352), (8392464, 'bpl', 8392884), (8392520, 'bpl', 8392600), (8392576, 'b', 8392620), (8392616, 'b', 8392620), (8392680, 'bpl', 8392760), (8392756, 'b', 8392780), (8392776, 'b', 8392780), (8392880, 'b', 8393300), (8392936, 'bpl', 8392996), (8392992, 'b', 8393016), (8393012, 'b', 8393016), (8393076, 'bpl', 8393180), (8393152, 'b', 8393200), (8393196, 'b', 8393200), (8393388, 'bne', 8394596), (8393508, 'bpl', 8393928), (8393564, 'bpl', 8393652), (8393620, 'b', 8393672), (8393668, 'b', 8393672), (8393732, 'bpl', 8393816), (8393808, 'b', 8393836), (8393832, 'b', 8393836), (8393920, 'b', 8394304), (8393980, 'bpl', 8394040), (8394036, 'b', 8394060), (8394056, 'b', 8394060), (8394120, 'bpl', 8394200), (8394196, 'b', 8394220), (8394216, 'b', 8394220), (8394592, 'b', 8395548), (8394676, 'bpl', 8395100), (8394732, 'bpl', 8394804), (8394788, 'b', 8394824), (8394820, 'b', 8394824), (8394888, 'bpl', 8394980), (8394968, 'b', 8395004), (8395000, 'b', 8395004), (8395096, 'b', 8395496), (8395152, 'bpl', 8395216), (8395212, 'b', 8395240), (8395236, 'b', 8395240), (8395304, 'bpl', 8395392), (8395380, 'b', 8395412), (8395408, 'b', 8395412), (8395584, 'bne', 8397320), (8395704, 'bpl', 8396124), (8395760, 'bpl', 8395852), (8395816, 'b', 8395872), (8395868, 'b', 8395872), (8395932, 'bpl', 8396032), (8396008, 'b', 8396052), (8396048, 'b', 8396052), (8396112, 'b', 8396480), (8396176, 'bpl', 8396244), (8396232, 'b', 8396264), (8396260, 'b', 8396264), (8396324, 'bpl', 8396404), (8396400, 'b', 8396424), (8396420, 'b', 8396424), (8397052, 'beq', 8397148), (8397308, 'b', 8398296), (8397400, 'bpl', 8397760), (8397456, 'bpl', 8397516), (8397512, 'b', 8397536), (8397532, 'b', 8397536), (8397596, 'bpl', 8397676), (8397672, 'b', 8397696), (8397692, 'b', 8397696), (8397756, 'b', 8398124), (8397812, 'bpl', 8397872), (8397868, 'b', 8397892), (8397888, 'b', 8397892), (8397952, 'bpl', 8398048), (8398028, 'b', 8398068), (8398064, 'b', 8398068), (8398332, 'bne', 8399192), (8398452, 'bpl', 8398852), (8398508, 'bpl', 8398584), (8398564, 'b', 8398604), (8398600, 'b', 8398604), (8398664, 'bpl', 8398744), (8398740, 'b', 8398764), (8398760, 'b', 8398764), (8398848, 'b', 8398900), (8399188, 'b', 8399768), (8399272, 'bpl', 8399668), (8399328, 'bpl', 8399388), (8399384, 'b', 8399408), (8399404, 'b', 8399408), (8399468, 'bpl', 8399556), (8399544, 'b', 8399576), (8399572, 'b', 8399576), (8399660, 'b', 8399716), (8399804, 'bne', 8400900), (8400100, 'bpl', 8400500), (8400156, 'bpl', 8400224), (8400212, 'b', 8400244), (8400240, 'b', 8400244), (8400304, 'bpl', 8400388), (8400380, 'b', 8400408), (8400404, 'b', 8400408), (8400464, 'b', 8400544), (8400896, 'b', 8401452), (8400980, 'bpl', 8401356), (8401036, 'bpl', 8401100), (8401092, 'b', 8401120), (8401116, 'b', 8401120), (8401180, 'bpl', 8401268), (8401256, 'b', 8401288), (8401284, 'b', 8401288), (8401344, 'b', 8401400), (8401488, 'bne', 8402940), (8401608, 'bpl', 8401940), (8401664, 'bpl', 8401724), (8401720, 'b', 8401744), (8401740, 'b', 8401744), (8401804, 'bpl', 8401884), (8401880, 'b', 8401904), (8401900, 'b', 8401904), (8401936, 'b', 8402292), (8401992, 'bpl', 8402052), (8402048, 'b', 8402072), (8402068, 'b', 8402072), (8402132, 'bpl', 8402240), (8402208, 'b', 8402260), (8402256, 'b', 8402260), (8402920, 'b', 8403792), (8403020, 'bpl', 8403368), (8403076, 'bpl', 8403152), (8403132, 'b', 8403172), (8403168, 'b', 8403172), (8403232, 'bpl', 8403312), (8403308, 'b', 8403332), (8403328, 'b', 8403332), (8403364, 'b', 8403692), (8403420, 'bpl', 8403480), (8403476, 'b', 8403500), (8403496, 'b', 8403500), (8403560, 'bpl', 8403640), (8403636, 'b', 8403660), (8403656, 'b', 8403660)],
        semantics=('LoadWorldUI -[hostMultiLANButton:] @0x007fff48 (3883 words, 187 branches, 76 calls, census). Handler of the LAN-host button: it moves the screen to the host-setup state and then lazily builds/refreshes every widget of that screen; it is the largest body in the class (window 0x7fff48..0x00803bf4 = the ARM.exidx bound, next IMP -[startTouch:]). ENTRY (0x7fff48..0x7fff9c): push {r4-r8,sl,fp,lr}; fp=sp+0x18; sub sp,#0x810; PIC anchor from cell 0x00800eb4=0x0085fb94 (resolves to 0x105faf4); self/_cmd/arg spilled to [fp,-0x20]/[-0x24]/[-0x28]; movw ip,#0 (the nil used by all guards). First action: self->state = 4 - movw r4,#4 (0x7fff68) stored through the OBJC_IVAR_$_LoadWorldUI.state@40 offset variable (ivar cell 0x00800ebc=0xffffdfc8, slot 0x105dabc): the LAN button selects state 4, the host-setup screen whose active buttons are backButton / hostNickNameButton / hostPicButton / hostPvpButton / hostNowButton in -[startTouch:] and which -[renderFrame:projectionMatrix:] draws. WIDGET SECTIONS: seven guard blocks `cmp self-><widget>,#0; bne <refresh block>` (bne at 0x7fffa8, 0x8008d4, 0x8012ac, 0x801b40, 0x8025fc, 0x802bbc, 0x803250); each build path allocates exactly one widget and stores it into its ivar, each refresh path (jumped to when the ivar is non-nil) re-runs setString:/setFrame: with the current window size and then falls through to the next guard - (1) hostNickNameTitleTextView@100 stored at 0x800478: MJTextView (class cell 0x800f94) via initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:; the string is picked by comparing windowInfo->[+0] against vldr 415.0 (pool 0x8002c0 = 0x43cf8000) and `movmi r4, lr`: CFSTR 0xf91898 "YOUR ALIAS:" when the value < 415.0, else CFSTR 0xf918a8 "YOUR NICKNAME:" (the same threshold is re-evaluated in the refresh block at 0x80048c..0x8004f0 with the two CFString cells 0x801398/0x80139c); font = +[BitmapFont standardFont] (class cell 0x8013a0, selref 0x8013a4, bl objc_msgSend 0x8003c4); colour argument packed as a full-white {1,1,1,1} by the 4-float helper bl 0x7ed8c4 from mov r2,#0x3f800000. (2) hostNickNameButton@104 stored at 0x800df0: MJButton with texture "textEntry.png" (CFSTR 0xf91ae8, cell 0x801c44) and title [self->hostUserName@152 uppercaseString] (hostUserName cell 0x801cfc=0xffffdfe8, selref 0x801d54, bl objc_msgSend 0x800d90), then initWithFrame:cache:windowInfo:title: (selref 0x801d58) and setTarget:self action:@selector(hostNickNameButton:) (selref 0x801c3c, 0x800e74). (3) hostPicTextView@108 stored at 0x80175c: MJTextView with CFSTR 0xf91ba8 "YOUR PIC:" (cell 0x8026e8, 0x801734) plus setTitleAlignment: (selref 0x801c2c). (4) hostPicButton@112 stored at 0x802014: MJButton skinned with CFSTR 0xf91858 "InventoryButtonBackgroundSelected.png" (selref 0x8018dc-setBackgroundSelectedTexture: 0x8020c4) and CFSTR 0xf91868 "InventoryButtonBackground.png" (selref setBackgroundTexture: 0x802060); inside this section a `cmp; beq 0x80215c` (0x8020fc) guards the self->picTexture@148 branch (cell 0x802e54=0xffffe034, reads at 0x801ecc/0x802118/0x802544, textureNamed: selref 0x801c48) and the action selector hostPicButton: is wired at 0x8021a4. (5) hostPvpTitleTextView@116 stored at 0x802950: MJTextView with CFSTR "PVP:" (0x802928). (6) hostPvpEnabled@160 stored as a byte at 0x802c98: = ![[NSUserDefaults standardUserDefaults] boolForKey:@"pvpDisabledHost"] (selrefs 0x802c28 standardUserDefaults / 0x802c60 boolForKey:, CFSTR "pvpDisabledHost" at 0x802bfc; the result is sign-extended, inverted by `eor r0,r0,#1` and masked with #1 before the strb). (7) hostPvpButton@120 stored at 0x802f88: MJToggleButton (class cell 0x802bec) with setOn:self->hostPvpEnabled (hostPvpEnabled reads at 0x802bf4/0x802ebc, selref setOn: 0x802ff0) and setTarget:self action:@selector(hostPvpButton:) (0x802fa4). (8) hostNowButton@124 stored at 0x8036ec: MJButton titled CFSTR "HOST GAME" (0x8036b8) with the green skin "InventoryButtonBackgroundGreen.png"/"InventoryButtonBackgroundSelectedGreen.png" (0x8035d8/0x8035b0) and setTarget:self action:@selector(hostNowButton:) (0x8037d4); the method then falls into `b 0x803b50` (0x8037e8) and the epilogue `sub sp,fp,#0x18; pop {r4,r5,r6,r7,r8,sl,fp,pc}` at 0x803b50-0x803b54, immediately followed by the literal pool up to 0x00803bf0. LAYOUT MATH AND CONSTANTS: every section begins `movw r0,#0x19f` (415) plus `vldr s0,[<section pool>]`, then loads a float field of self->windowInfo@8 (vldr sN,[windowInfo+0/+4/+8/+0xc]) and compares with `vcmpe.f32` + `vmrs apsr_nzcv,fpscr`; 62 of the 187 branches are the resulting `bpl` guards that skip a recomputation of a cached frame value when the current value is not smaller. Float constants read straight from the ELF literal pools (file offset = vaddr, struct-decoded): 415.0 = 0x43cf8000 (63 loads, first 0x7fffb0), 48.0 = 0x42400000 (34), 160.0 = 0x43200000 (24, first 0x800060), 0.0 (24), -44.0 = 0xc2300000 (24), 96.0 = 0x42c00000 (2); the GNU cross-check listing adds the VFP immediates vmov.f32 s2,#36 (24x), #40 (10x) and #16 (4x) that exist only as encoded immediates. CALLS: 76 = 18 direct `bl loc.imp.objc_msgSend` + 29 `blx rN` (16 r3, 10 lr, 2 ip, 1 r4; 18 of them resolve to objc_msgSend through the GOT pointer slot 0x105b7a0 loaded by cells 0x800f8c/0x8030c8/0x803b68, the rest dispatch the same kind of pointer spilled to stack locals - objc_msgSend is the only import materialised anywhere in the body) + 26 `bl 0x7ed878` + 3 `bl 0x7ed8c4`, the two byte-identical 16-byte 4-float struct packers already documented in the E156 NetPlayerButton batch (`out[0..12] = r1,r2,r3,[sp]`), used here 29 times to materialise CGRects/CGPoints/colour structs. No objc_msgSendSuper2 anywhere. Ivars read (all through OBJC_IVAR_$_LoadWorldUI offset cells, verified by an independent cell census of 100 distinct pool cells / 266 pool loads): windowInfo 117 sites, cache 10, hostPicButton 6, hostNickNameTitleTextView 3, hostNickNameButton 3, hostPicTextView 3, picTexture 3, hostPvpTitleTextView 3, hostPvpButton 3, hostNowButton 3, hostPvpEnabled 2, state 1, hostUserName 1.'),
    ),
    dict(
        name='lwu_12',
        method='LoadWorldUI -[hostNickNameButton:]',
        types='v12@0:4@8',
        start=8414604,
        end=8415540,
        disasm='disasm_worldtileloader_lwu_12.txt',
        base_add=8414620,
        base_literal=8415536,
        boundary='ARM.exidx end 0x00806934 (listing bound); next ObjC IMP 0x00806934 LoadWorldUI -[onlinePicButton:]',
        selectors={
                 0x8068e4: (15211376, 'show'),
                 0x8068ec: (15211440, 'setText:'),
                 0x8068f0: (15211476, 'title'),
                 0x8068f8: (15211464, 'setDelegate:'),
                 0x8068fc: (15211520, 'setReturnKeyType:'),
                 0x806900: (15211516, 'setKeyboardType:'),
                 0x806904: (15211512, 'setEnablesReturnKeyAutomatically:'),
                 0x806908: (15211508, 'setAutocorrectionType:'),
                 0x80690c: (15211444, 'textFieldAtIndex:'),
                 0x806910: (15211504, 'setAlertViewStyle:'),
                 0x806920: (15211500, 'initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:'),
                 0x806924: (15211120, 'alloc'),
        },
        imports={
                 0x8068e0: (17151904, 'objc_msgSend'),
                 0x806914: (16325688, '__CFConstantStringClassReference'),
                 0x806918: (16325656, '__CFConstantStringClassReference'),
                 0x80691c: (16325672, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8068e8: (17161036, 'OBJC_IVAR_$_LoadWorldUI.textEntryAlertView', 64),
                 0x8068f4: (17160960, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameButton', 104),
                 0x80692c: (17161044, 'OBJC_IVAR_$_LoadWorldUI.textEntryType', 44),
        },
        classes={
                 0x806928: (15247300, 'OBJC_CLASS_$_UIAlertView'),
        },
        instructions=[(8414604, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8415536, 'addeq sb, r5, r0, asr r5')],
        calls=[(8415020, 'blx ip'), (8415088, 'blx r6'), (8415144, 'blx r3'), (8415184, 'blx r3'), (8415212, 'blx r3'), (8415240, 'blx r3'), (8415264, 'blx r3'), (8415288, 'blx r3'), (8415324, 'blx r3'), (8415376, 'blx ip'), (8415408, 'blx r3'), (8415444, 'blx r3')],
        branches=[],
        semantics=('LoadWorldUI -[hostNickNameButton:] @0x0080658c (234 words, 0 branches, 12 calls): opens the \'Your Nickname\' entry alert. It first writes self->textEntryType@44 = 1 (int, 0x008066f8) and then builds a UIAlertView by hand (all selectors/constants are hoisted into stack slots before the sends): CALL0 0x0080672c = objc_msgSend(UIAlertView class (classref 0x00e8a7c4 dereferenced with ldr), @selector(alloc)); CALL1 0x00806770 = objc_msgSend(alert, @selector(initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:), @"Your Nickname" (CFString 0x00f91c38), nil message, delegate = self, @"Cancel" (0x00f91c18), @"Done" (0x00f91c28), nil terminator) - the two varargs plus self are passed on the stack ([sp],[sp,4],[sp,8],[sp,0xc]); the returned +1 object is stored straight into textEntryAlertView@64 with an inline \'str r0,[self+64]\' (0x00806784, no release of an old value observed). Then the plain-text configuration chain on the same alert view (r0 reloaded from the ivar each time): CALL2 0x008067a8 = setAlertViewStyle: 2; CALL3 0x008067d0 = objc_msgSend(alert, @selector(textFieldAtIndex:), 0) whose result is kept at [fp,-0x28]; CALL4 0x008067ec = [textField setAutocorrectionType:1] (UITextAutocorrectionTypeNo); CALL5 0x00806808 = [textField setEnablesReturnKeyAutomatically:(sxtb)1]; CALL6 0x00806820 = [textField setKeyboardType:1]; CALL7 0x00806838 = [textField setReturnKeyType:9] (UIReturnKeyDone); CALL8 0x0080685c = [textField setDelegate:self]. Finally CALL9 0x00806890 = objc_msgSend(self->hostNickNameButton@104 (via .got 0x0105db00), @selector(title)), whose string is fed to CALL10 0x008068b0 = [textField setText:buttonTitle] (pre-fills the field with the current nickname), and CALL11 0x008068d4 = [self->textEntryAlertView show]. Frame push {r4,r5,r6,r7,r8,sl,fp,lr}/sub sp,#0xb0; the button argument (r2) is spilled to [fp,-0x24] and never read.'),
    ),
    dict(
        name='lwu_13',
        method='LoadWorldUI -[hostNowButton:]',
        types='v12@0:4@8',
        start=8418912,
        end=8419016,
        disasm='disasm_worldtileloader_lwu_13.txt',
        base_add=8418928,
        base_literal=8419012,
        boundary='ARM.exidx end 0x008076c8 (listing bound); next ObjC IMP 0x008076c8 LoadWorldUI -[cloudConnectionRequestSucceededWithHost:port:key:]',
        selectors={
                 0x8076bc: (15211564, 'hostLANGameInCurrentWorld'),
        },
        imports={
                 0x8076b8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8076c0: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
        },
        classes={},
        instructions=[(8418912, 'push {r4, sl, fp, lr}'), (8419012, 'addeq r8, r5, ip, ror r4')],
        calls=[(8418988, 'blx ip')],
        branches=[],
        semantics=('LoadWorldUI -[hostNowButton:] @0x00807660 (26 words, 0 branches, 1 call): one-send handler, structurally identical to lwu_02 - PIC base 0x0105faf4 from pool cell 0x008076c4 (0x85847c + pc at 0x00807670); objc_msgSend from .got 0x0105b7a0 (pool cell 0x008076b8 = 0xffffbcac); selref @selector(hostLANGameInCurrentWorld) at 0x00e81c2c (pool cell 0x008076bc = 0xffe22138); delegate ivar-offset cell @4 (.got 0x0105dac8 via pool cell 0x008076c0 = 0xffffdfd4). Body: spill r0/r1/r2 to [sp,0xc]/[sp,8]/[sp,4], reload self from [sp,0xc], send objc_msgSend(self->delegate@4, @selector(hostLANGameInCurrentWorld)) with blx ip at 0x008076ac, then sub sp,fp,#8 / pop {r4,sl,fp,pc}. The button argument (r2) is dead (spilled, never read).'),
    ),
    dict(
        name='lwu_14',
        method='LoadWorldUI -[hostPicButton:]',
        types='v12@0:4@8',
        start=8415936,
        end=8416288,
        disasm='disasm_worldtileloader_lwu_14.txt',
        base_add=8415952,
        base_literal=8416284,
        boundary='ARM.exidx end 0x00806c20 (listing bound); next ObjC IMP 0x00806c20 LoadWorldUI -[imageWithImage:scaledToSize:]',
        selectors={
                 0x806c08: (15211524, 'frame'),
                 0x806c18: (15211528, 'startImagePickerWithDelegate:forRect:cropSize:'),
        },
        imports={},
        ivars={
                 0x806c0c: (17161048, 'OBJC_IVAR_$_LoadWorldUI.avatarPickButton', 164),
                 0x806c10: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
        },
        classes={},
        instructions=[(8415936, 'push {r4, r5, fp, lr}'), (8416284, 'addeq sb, r5, ip, lsl r0')],
        calls=[(8416044, 'bl loc.imp.objc_msgSend_stret'), (8416080, 'bl sym.imp.memset'), (8416180, 'bl 0x806a94'), (8416252, 'bl loc.imp.objc_msgSend')],
        branches=[(8416028, 'beq', 8416052), (8416048, 'b', 8416084)],
        semantics=('LoadWorldUI -[hostPicButton:] @0x00806ac0 (88 words, 2 branches, 4 calls): avatar-picture picker entry; stores the tapped button into self->avatarPickButton@164 (ivar cell 0x00806c0c), then captures the sender button\'s frame: sender != nil (cmp against a movw-zero) -> bl loc.imp.objc_msgSend_stret 0x00806b2c with out=&[fp-0x28], receiver=sender, SEL=@selector(frame) (cell 0x00806c08); sender == nil -> movw r2,#0x10 + bl sym.imp.memset zeros the same 16 bytes (fill value forced with and r1,r1,#0xff). Then bl 0x00806a94 - a leaf CGSize packer (sub sp,#8; vmov s0,r2 / s2,r1; spills both; writes w=r1 to [r0] and h=r2 to [r0,#4]) - fills [sp,0x30] with cropSize {320.0f,320.0f} (movw/movt 0x43a00000, passed in r1=r2=ip). Final send via loc.imp.objc_msgSend 0x00806bfc: receiver self->delegate@4 (cell 0x00806c10), SEL startImagePickerWithDelegate:forRect:cropSize: (cell 0x00806c18), arg1=self, forRect: the captured sender CGRect (r3/[sp]/[sp+4]/[sp+8]), cropSize: 320x320 ([sp+0xc]/[sp+0x10]). Base T=pc+0x85901c=0x0105faf4. Byte-identical twin of lwu_25 (onlinePicButton:): same instruction stream, only pool constants differ.'),
    ),
    dict(
        name='lwu_15',
        method='LoadWorldUI -[hostPvpButton:]',
        types='v12@0:4@8',
        start=8418504,
        end=8418912,
        disasm='disasm_worldtileloader_lwu_15.txt',
        base_add=8418520,
        base_literal=8418908,
        boundary='ARM.exidx end 0x00807660 (listing bound); next ObjC IMP 0x00807660 LoadWorldUI -[hostNowButton:]',
        selectors={
                 0x807644: (15211560, 'setBool:forKey:'),
                 0x80764c: (15211160, 'standardUserDefaults'),
                 0x807654: (15211404, 'setOn:'),
        },
        imports={
                 0x80763c: (16325576, '__CFConstantStringClassReference'),
                 0x807640: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x807648: (17161032, 'OBJC_IVAR_$_LoadWorldUI.hostPvpEnabled', 160),
                 0x807658: (17160944, 'OBJC_IVAR_$_LoadWorldUI.hostPvpButton', 120),
        },
        classes={
                 0x807650: (15247244, 'OBJC_CLASS_$_NSUserDefaults'),
        },
        instructions=[(8418504, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8418908, 'addeq r8, r5, r4, lsl r6')],
        calls=[(8418756, 'blx lr'), (8418788, 'blx r3'), (8418864, 'blx lr')],
        branches=[],
        semantics=('LoadWorldUI -[hostPvpButton:] @0x008074c8 (102 words, 0 branches, 3 calls): tap handler for the host PvP toggle. Constants hoisted into registers at entry: ip = CFString literal 0x00f91bc8 \'pvpDisabledHost\' (pool cell 0x0080763c); r5 = selref @selector(setBool:forKey:) (0x00e81c28); r6 = &OBJC_IVAR_$_LoadWorldUI.hostPvpEnabled (offset 160, .got slot 0x0105db48); r8 = selref @selector(standardUserDefaults) (0x00e81a98); sl = OBJC_CLASS_$_NSUserDefaults classref (0x00e8a78c, dereferenced later with ldr r1,[r0]). self is parked in the scratch slot [fp,-0x1c] and the button argument is spilled to [fp,-0x24] and never read. Sequence: newVal = !self->hostPvpEnabled (ldrsb self+160, cmp/movne 1, eor 1, and 1 -> 0x00807548..0x0080755c) is written straight back with strb (0x0080756c); then CALL0 0x008075c4 = objc_msgSend(r0 = self->hostPvpButton@120 loaded from .got 0x0105daf0, r1 = @selector(setOn:), r2 = (sxtb)newVal) so the MJToggleButton tracks the flag; then CALL1 0x008075e4 = objc_msgSend(NSUserDefaults class, @selector(standardUserDefaults)); then CALL2 0x00807630 = objc_msgSend(defaults, @selector(setBool:forKey:), (BOOL)!hostPvpEnabled, \'pvpDisabledHost\') - the persisted BOOL is recomputed from the just-stored ivar (ldrsb + eor 1), i.e. the key stores the inverted, \'disabled\' sense of hostPvpEnabled. No branch instruction in the body; registers r4..sl are spilled to [sp,4..0x1c] around the first send (Apportable save-across-send idiom). Frame push {r4,r5,r6,r7,r8,sl,fp,lr}/sub sp,#0x38.'),
    ),
    dict(
        name='lwu_16',
        method='LoadWorldUI -[hostPvpEnabled]',
        types='c8@0:4',
        start=8423344,
        end=8423404,
        disasm='disasm_worldtileloader_lwu_16.txt',
        base_add=8423352,
        base_literal=8423400,
        boundary='ARM.exidx end 0x00808828; body trimmed at the next IMP 0x008087ec LoadWorldUI -[state]',
        selectors={},
        imports={},
        ivars={
                 0x8087e4: (17161032, 'OBJC_IVAR_$_LoadWorldUI.hostPvpEnabled', 160),
        },
        classes={},
        instructions=[(8423344, 'sub sp, sp, 8'), (8423400, 'addeq r7, r5, r4, lsr r3')],
        calls=[],
        branches=[],
        semantics=('LoadWorldUI -[hostPvpEnabled] @0x008087b0 (15 words, 0 calls, 0 branches; read): Apportable offset-cell char getter (types c8@0:4). PIC base = pc(0x008087b8+8=0x008087c0) + pool cell 0x008087e8 value 0x857334 = 0x0105faf4; ivar cell 0x008087e4 holds 0xffffe054 (= base-0x1fAC) -> GOT slot 0x0105db48 -> __objc_ivar slot 0x00f33d18 whose content is 160, so it returns \'ldrsb r0,[self+160]\' = OBJC_IVAR_$_LoadWorldUI.hostPvpEnabled. No \'dmb ish\' (plain scalar getter). Body stops at the next ObjC IMP 0x008087ec -[state] (roster trim note); the ARM.exidx range printed for this IMP runs on to 0x00808828.'),
    ),
    dict(
        name='lwu_17',
        method='LoadWorldUI -[hostUserName]',
        types='@8@0:4',
        start=8423208,
        end=8423276,
        disasm='disasm_worldtileloader_lwu_17.txt',
        base_add=8423232,
        base_literal=8423272,
        boundary='ARM.exidx end 0x008087b0; body trimmed at the next IMP 0x0080876c LoadWorldUI -[hostUserPhoto]',
        selectors={},
        imports={},
        ivars={
                 0x808764: (17160924, 'OBJC_IVAR_$_LoadWorldUI.hostUserName', 152),
        },
        classes={},
        instructions=[(8423208, 'sub sp, sp, 0xc'), (8423272, 'addeq r7, r5, ip, lsr 7')],
        calls=[],
        branches=[],
        semantics=('LoadWorldUI -[hostUserName] @0x00808728 (17 words, 0 calls, 0 branches; read): offset-cell object getter (types @8@0:4). PIC base = pc(0x00808740+8=0x00808748) + pool cell 0x00808768 value 0x8573ac = 0x0105faf4; ivar cell 0x00808764 holds 0xffffdfe8 (base-0x2018) -> GOT slot 0x0105dadc -> __objc_ivar slot 0x00f33cac whose content is 152, so the returned object is self+152 = OBJC_IVAR_$_LoadWorldUI.hostUserName. The load is followed by \'dmb ish\' (ARC object getter idiom) and the result is spilled to [sp,8] and reloaded before the epilogue. Body stops at the next ObjC IMP 0x0080876c -[hostUserPhoto] (roster trim note); the ARM.exidx range printed for this IMP runs to 0x008087b0.'),
    ),
    dict(
        name='lwu_18',
        method='LoadWorldUI -[hostUserPhoto]',
        types='@8@0:4',
        start=8423276,
        end=8423344,
        disasm='disasm_worldtileloader_lwu_18.txt',
        base_add=8423300,
        base_literal=8423340,
        boundary='ARM.exidx end 0x008087b0 (listing bound); next ObjC IMP 0x008087b0 LoadWorldUI -[hostPvpEnabled]',
        selectors={},
        imports={},
        ivars={
                 0x8087a8: (17161004, 'OBJC_IVAR_$_LoadWorldUI.hostUserPhoto', 156),
        },
        classes={},
        instructions=[(8423276, 'sub sp, sp, 0xc'), (8423340, 'addeq r7, r5, r8, ror 6')],
        calls=[],
        branches=[],
        semantics=('LoadWorldUI -[hostUserPhoto] @0x0080876c (17 words, 0 calls, 0 branches; read): instruction-for-instruction twin of lwu_17 for a different ivar. PIC base = pc(0x00808784+8=0x0080878c) + 0x857368 = 0x0105faf4; ivar cell 0x008087a8 holds 0xffffe038 (base-0x1fc8) -> GOT slot 0x0105db2c -> __objc_ivar slot 0x00f33cc0 = 156, so it returns self+156 = OBJC_IVAR_$_LoadWorldUI.hostUserPhoto with \'dmb ish\' after the load and the usual [sp,8] spill/reload. Boundary is a true listing bound: the next ObjC IMP 0x008087b0 -[hostPvpEnabled].'),
    ),
    dict(
        name='lwu_19',
        method='LoadWorldUI -[imagePickerFinishedWithImage:]',
        types='v12@0:4@8',
        start=8416752,
        end=8418504,
        disasm='disasm_worldtileloader_lwu_19.txt',
        base_add=8416768,
        base_literal=8418500,
        boundary='ARM.exidx end 0x008074c8 (listing bound); next ObjC IMP 0x008074c8 LoadWorldUI -[hostPvpButton:]',
        selectors={
                 0x807454: (15211176, 'retain'),
                 0x80745c: (15211196, 'release'),
                 0x807460: (15211540, 'imageWithImage:scaledToSize:'),
                 0x807464: (15211220, 'setGlyphTexture:'),
                 0x807470: (15211248, 'initWithUIImage:'),
                 0x807474: (15211120, 'alloc'),
                 0x80747c: (15211552, 'copyItemAtPath:toPath:error:'),
                 0x807480: (15211232, 'defaultManager'),
                 0x807488: (15211548, 'removeItemAtPath:error:'),
                 0x807490: (15211228, 'stringWithFormat:'),
                 0x807498: (15211224, 'objectForKey:'),
                 0x8074a4: (15211208, 'objectAtIndex:'),
                 0x8074ac: (15211544, 'writeToFile:atomically:'),
                 0x8074b4: (15211240, 'stringByAppendingPathComponent:'),
                 0x8074b8: (15211556, 'setStatusBarHidden:'),
                 0x8074bc: (15211488, 'sharedApplication'),
        },
        imports={
                 0x807450: (17151904, 'objc_msgSend'),
                 0x80748c: (16324792, '__CFConstantStringClassReference'),
                 0x807494: (16324824, '__CFConstantStringClassReference'),
                 0x8074a0: (16324808, '__CFConstantStringClassReference'),
                 0x8074b0: (16324840, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x80744c: (17161004, 'OBJC_IVAR_$_LoadWorldUI.hostUserPhoto', 156),
                 0x807468: (17161000, 'OBJC_IVAR_$_LoadWorldUI.picTexture', 148),
                 0x80746c: (17161048, 'OBJC_IVAR_$_LoadWorldUI.avatarPickButton', 164),
                 0x80749c: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
        },
        classes={
                 0x807478: (15247260, 'OBJC_CLASS_$_CPTexture2D'),
                 0x807484: (15247252, 'OBJC_CLASS_$_NSFileManager'),
                 0x8074a8: (15247248, 'OBJC_CLASS_$_NSString'),
                 0x8074c0: (15247296, 'OBJC_CLASS_$_UIApplication'),
        },
        instructions=[(8416752, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8418500, 'addeq r8, r5, ip, ror 25')],
        calls=[(8416904, 'bl loc.imp.objc_msgSend'), (8416968, 'bl 0x806a94'), (8417008, 'bl loc.imp.objc_msgSend'), (8417024, 'blx r2'), (8417104, 'bl sym.UIImagePNGRepresentation'), (8417144, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (8417280, 'blx r4'), (8417300, 'blx r3'), (8417336, 'blx ip'), (8417380, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (8417784, 'blx r3'), (8417836, 'blx ip'), (8417888, 'blx ip'), (8417940, 'blx r4'), (8417976, 'blx r3'), (8418000, 'blx ip'), (8418032, 'blx r2'), (8418064, 'blx lr'), (8418112, 'blx ip'), (8418144, 'blx r3'), (8418180, 'blx r3'), (8418252, 'blx ip'), (8418344, 'blx lr'), (8418368, 'blx r3')],
        branches=[(8416800, 'beq', 8418264), (8417072, 'beq', 8418260), (8417124, 'beq', 8418256), (8418256, 'b', 8418260), (8418260, 'b', 8418264)],
        semantics=('LoadWorldUI -[imagePickerFinishedWithImage:] @0x00806df0 (438 words, 5 branches, 24 calls; [census-lite]): the avatar-photo completion pipeline. Slots: self [fp,-0x20], _cmd [fp,-0x24], image (=picker argument) [fp,-0x28], PIC base captured once into [fp,-0x40] (and re-derived at 0x00806e50). Nil guard first: if image == 0 (movw ip,0 / cmp) branch to the tail at 0x008073d8. Main chain - (1) ARC swap of the old photo: CALL0 0x00806e88 objc_msgSend(self->hostUserPhoto@156 (.got 0x0105db2c), @selector(release)) followed by the inline \'store 0\' into self+156 (0x00806e9c), then CALL1 0x00806ec8 = the 11-instruction CGSize packer at 0x00806a94, called as (out = fp-0x30, 64.0f, 64.0f) with both floats materialised by movw/movt #0x42800000, and CALL2 0x00806ef0 = objc_msgSend(self, @selector(imageWithImage:scaledToSize:) (selref 0x00e81c14), image, {64,64}) with the second CGSize word pushed via \'mov r2,sp / str r0,[r2]\'; the result is retained by CALL3 0x00806f00 (objc_msgSend(scaledImage, @selector(retain)) and stored into hostUserPhoto@156 at 0x00806f14; if that slot is still 0 (branch beq 0x00806f30) the whole disk/texture chain is skipped. (2) Disk write: CALL4 0x00806f50 UIImagePNGRepresentation(self->hostUserPhoto); if the data is 0 branch to 0x008073d0 (skip). Paths: CALL5 0x00806f78 NSSearchPathForDirectoriesInDomains(14 = NSApplicationSupportDirectory, 1 = NSUserDomainMask, YES), CALL6 0x00807000 objc_msgSend(paths, @selector(objectAtIndex:), 0) -> dir, CALL7 0x00807014 objc_msgSend(dir, @selector(stringByAppendingPathComponent:), @"avatar.png" (CFString 0x00f918e8)) -> [fp,-0x38] = staging path, CALL8 0x00807038 objc_msgSend(pngData, @selector(writeToFile:atomically:), stagingPath, YES) - the destination of the write. CALL9 0x00807064 repeats NSSearchPathForDirectoriesInDomains(14,1,YES) for the saves tree, then CALL10 0x008071f8 objc_msgSend(paths2, @selector(objectAtIndex:), 0) -> savesPath; CALL11 0x0080722c and CALL12 0x00807260 read objc_msgSend(self->gameSave@36 (.got 0x0105db24), @selector(objectForKey:), @"saveID" (0x00f918c8)) and @"playerID" (0x00f918d8); CALL13 0x00807294 = [NSString (classref 0x00e8a790) stringWithFormat:@"%@/saves/%@/avatar_%@_.png" (0x00f918b8), savesPath, saveID, playerID] (one vararg in r3, two on the stack) -> [fp,-0x3c] destination path. File manager: CALL14 0x008072b8 [NSFileManager (classref 0x00e8a794) defaultManager], CALL15 0x008072d0 [fm removeItemAtPath:dstPath error:NULL], CALL16 0x008072f0 [NSFileManager defaultManager] again, CALL17 0x00807310 [fm copyItemAtPath:stagingPath toPath:dstPath error:NULL] (error NULL pushed on the stack). (3) Texture rebuild: CALL18 0x00807340 objc_msgSend(self->picTexture@148 (.got 0x0105db28), @selector(release)), CALL19 0x00807360 [CPTexture2D (classref 0x00e8a79c) alloc], CALL20 0x00807384 objc_msgSend(alloc\'d, @selector(initWithUIImage:), self->hostUserPhoto) whose result is stored into picTexture@148 (0x00807398), then CALL21 0x008073cc objc_msgSend(self->avatarPickButton@164 (.got 0x0105db58), @selector(setGlyphTexture:), self->picTexture). (4) Tail at 0x008073d8, reached through the two unconditional branches at 0x008073d0/0x008073d4 from every early exit as well as by fall-through: CALL22 0x00807428 objc_msgSend([UIApplication classref 0x00e8a7c0 + ldr deref], @selector(sharedApplication)) and CALL23 0x00807440 objc_msgSend(app, @selector(setStatusBarHidden:), (sxtb)1 = YES). The 24 calls are a mix of 2 direct PLT objc_msgSend calls and blx through spilt registers; 0x806a94 is the only non-import direct \'bl\' helper. Frame push {r4,r5,r6,r7,r8,sl,fp,lr}/sub sp,#0x120.'),
    ),
    dict(
        name='lwu_20',
        method='LoadWorldUI -[imageWithImage:scaledToSize:]',
        types='@20@0:4@8{CGSize=ff}12',
        start=8416288,
        end=8416752,
        disasm='disasm_worldtileloader_lwu_20.txt',
        base_add=8416304,
        base_literal=8416748,
        boundary='ARM.exidx end 0x00806df0 (listing bound); next ObjC IMP 0x00806df0 LoadWorldUI -[imagePickerFinishedWithImage:]',
        selectors={
                 0x806de0: (15211532, 'size'),
                 0x806de4: (15211536, 'drawInRect:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(8416288, 'push {r4, r5, fp, lr}'), (8416748, 'strheq r8, [r5], ip')],
        calls=[(8416384, 'bl loc.imp.objc_msgSend_stret'), (8416420, 'bl sym.imp.memset'), (8416496, 'bl loc.imp.objc_msgSend_stret'), (8416532, 'bl sym.imp.memset'), (8416604, 'bl sym.UIGraphicsBeginImageContextWithOptions'), (8416648, 'bl 0x7ed878'), (8416700, 'bl loc.imp.objc_msgSend'), (8416704, 'bl sym.UIGraphicsGetImageFromCurrentImageContext'), (8416712, 'bl sym.UIGraphicsEndImageContext')],
        branches=[(8416368, 'beq', 8416392), (8416388, 'b', 8416424), (8416440, 'bne', 8416568), (8416480, 'beq', 8416504), (8416500, 'b', 8416536), (8416552, 'bne', 8416568), (8416564, 'b', 8416724)],
        semantics=('LoadWorldUI -[imageWithImage:scaledToSize:] @0x00806c20 (116 words, 7 branches, 9 calls): instance helper that returns image itself when it already has the requested size, otherwise re-renders it at 1.0 scale. Prologue saves w = r3 (first CGSize word) to [fp,-0x18], h = [fp,8] (second CGSize word, passed on the stack) to [fp,-0x14], image (r2) to [fp,-0x24]; PIC base 0x0105faf4 from pool cell 0x00806dec; r5 = selref @selector(size) (0x00e81c0c). Both size reads are objc_msgSend_stret with the Apportable nil-guard: if image==0 the buffer is zeroed by memset(dest, 0, 8) instead (0x00806ca4 on buffer fp-0x30, 0x00806d14 on buffer fp-0x38). Fast path: vcmpe s0=[fp,-0x30] (width of the returned CGSize) vs s2=[fp,-0x18] (w), and s0=[fp,-0x34] (height of the second returned CGSize) vs s2=[fp,-0x14] (h) - if both are equal it stores image into the result slot [fp,-0xc] and returns it (b 0x00806dd4). Slow path (0x00806d38): UIGraphicsBeginImageContextWithOptions(CGSize(w,h), opaque = 0, scale = 0x3f800000 = 1.0f) - note the opaque flag is NO; the destination rect is built by the 19-instruction float4 packer at 0x007ed878 (out = {0, 0, w, h}, called with r1=r2=0, r3=w, [sp]=h, r0=&rect at sp+0x30); the same r0 = image is saved at [sp,8]; then objc_msgSend(image, @selector(drawInRect:), rect) (0x00806dbc, rect words 3/4 pushed by str r0,[sp]/str ip,[sp,4]), UIGraphicsGetImageFromCurrentImageContext() (result parked at [sp,0x2c]) and UIGraphicsEndImageContext(); the new UIImage is stored into [fp,-0xc] and returned. Frame push {r4,r5,fp,lr}/sub sp,#0x78; return type id.'),
    ),
    dict(
        name='lwu_21',
        method='LoadWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:]',
        types='@24@0:4@8^{WindowInfo=ffffffff}12@16@20',
        start=8306800,
        end=8312952,
        disasm='disasm_worldtileloader_lwu_21.txt',
        base_add=8306816,
        base_literal=8310240,
        boundary='ARM.exidx end 0x007ed878 (listing bound); next ObjC IMP 0x007ed954 LoadWorldUI -[dismissAlertViews]',
        selectors={
                 0x7ecde8: (15211116, 'init'),
                 0x7ecdf8: (15211120, 'alloc'),
                 0x7ed2ec: (15211124, 'standardFont'),
                 0x7ed2f0: (15211128, 'initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:'),
                 0x7ed7c8: (15211120, 'alloc'),
                 0x7ed7e0: (15211124, 'standardFont'),
                 0x7ed7e4: (15211128, 'initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:'),
                 0x7ed7f4: (15211152, 'setTarget:action:'),
                 0x7ed7f8: (15211148, 'playButton:'),
                 0x7ed800: (15211144, 'setBackgroundSelectedTexture:'),
                 0x7ed808: (15211136, 'textureNamed:'),
                 0x7ed80c: (15211140, 'setBackgroundTexture:'),
                 0x7ed820: (15211132, 'initWithFrame:cache:windowInfo:title:'),
                 0x7ed828: (15211164, 'integerForKey:'),
                 0x7ed82c: (15211160, 'standardUserDefaults'),
                 0x7ed834: (15211156, 'optionsButton:'),
                 0x7ed850: (15211168, 'setHidden:'),
                 0x7ed868: (15211176, 'retain'),
                 0x7ed870: (15211172, 'stringForKey:'),
                 0x7ed874: (15211180, 'defaultUserName'),
        },
        imports={
                 0x7ecde4: (17151900, 'objc_msgSendSuper2'),
                 0x7ecdf4: (17151904, 'objc_msgSend'),
                 0x7ed40c: (16324600, '__CFConstantStringClassReference'),
                 0x7ed7c4: (17151904, 'objc_msgSend'),
                 0x7ed804: (16324648, '__CFConstantStringClassReference'),
                 0x7ed810: (16324632, '__CFConstantStringClassReference'),
                 0x7ed814: (16324616, '__CFConstantStringClassReference'),
                 0x7ed824: (16324712, '__CFConstantStringClassReference'),
                 0x7ed83c: (16324696, '__CFConstantStringClassReference'),
                 0x7ed840: (16324680, '__CFConstantStringClassReference'),
                 0x7ed844: (16324664, '__CFConstantStringClassReference'),
                 0x7ed858: (16324728, '__CFConstantStringClassReference'),
                 0x7ed86c: (16324744, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7ecdf0: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7ece00: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x7ece04: (17160896, 'OBJC_IVAR_$_LoadWorldUI.cloudInterface', 16),
                 0x7ece08: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
                 0x7ece0c: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
                 0x7ed2e0: (17160908, 'OBJC_IVAR_$_LoadWorldUI.blockheadNamesTextView', 28),
                 0x7ed7c0: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7ed7d0: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
                 0x7ed7d4: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
                 0x7ed7fc: (17160912, 'OBJC_IVAR_$_LoadWorldUI.playButton', 20),
                 0x7ed838: (17160916, 'OBJC_IVAR_$_LoadWorldUI.optionsButton', 24),
                 0x7ed854: (17160920, 'OBJC_IVAR_$_LoadWorldUI.disabledTextView', 56),
                 0x7ed864: (17160924, 'OBJC_IVAR_$_LoadWorldUI.hostUserName', 152),
        },
        classes={
                 0x7ecdec: (15252832, 'OBJC_CLASS_$_LoadWorldUI'),
                 0x7ecdfc: (15247232, 'OBJC_CLASS_$_MJTextView'),
                 0x7ed2dc: (15247240, 'OBJC_CLASS_$_MJButton'),
                 0x7ed2e8: (15247236, 'OBJC_CLASS_$_BitmapFont'),
                 0x7ed7cc: (15247232, 'OBJC_CLASS_$_MJTextView'),
                 0x7ed7d8: (15247240, 'OBJC_CLASS_$_MJButton'),
                 0x7ed7dc: (15247236, 'OBJC_CLASS_$_BitmapFont'),
                 0x7ed830: (15247244, 'OBJC_CLASS_$_NSUserDefaults'),
        },
        instructions=[(8306800, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8312948, 'invalid')],
        calls=[(8306908, 'blx r6'), (8307148, 'blx ip'), (8307572, 'bl 0x7ed878'), (8307656, 'bl loc.imp.objc_msgSend'), (8307696, 'bl 0x7ed8c4'), (8307828, 'bl loc.imp.objc_msgSend'), (8307880, 'blx ip'), (8308372, 'bl 0x7ed878'), (8308536, 'bl 0x7ed878'), (8308804, 'bl 0x7ed878'), (8309256, 'bl loc.imp.objc_msgSend'), (8309344, 'blx lr'), (8309376, 'blx r3'), (8309444, 'blx lr'), (8309476, 'blx r3'), (8309524, 'blx lr'), (8309556, 'blx r3'), (8310048, 'bl 0x7ed878'), (8310120, 'bl 0x7ed878'), (8310416, 'bl 0x7ed878'), (8310872, 'bl loc.imp.objc_msgSend'), (8310960, 'blx lr'), (8310992, 'blx r3'), (8311060, 'blx lr'), (8311092, 'blx r3'), (8311140, 'blx lr'), (8311172, 'blx r3'), (8311192, 'blx r3'), (8311196, 'bl 0x7ed910'), (8311284, 'blx r3'), (8311740, 'bl 0x7ed878'), (8311812, 'bl 0x7ed878'), (8312048, 'bl 0x7ed878'), (8312180, 'bl loc.imp.objc_msgSend'), (8312220, 'bl 0x7ed8c4'), (8312352, 'bl loc.imp.objc_msgSend'), (8312412, 'blx ip'), (8312532, 'blx r3'), (8312552, 'blx r3'), (8312568, 'blx r2'), (8312704, 'blx r2'), (8312720, 'blx r2')],
        branches=[(8306936, 'beq', 8312748), (8307252, 'bpl', 8307272), (8307264, 'b', 8307420), (8307332, 'bmi', 8307400), (8307924, 'bmi', 8307984), (8307980, 'bpl', 8308544), (8308156, 'bpl', 8308172), (8308168, 'b', 8308320), (8308232, 'bmi', 8308300), (8308540, 'b', 8308808), (8308596, 'bpl', 8308676), (8308652, 'b', 8308696), (8308692, 'b', 8308696), (8309600, 'bmi', 8309660), (8309656, 'bpl', 8310128), (8309832, 'bpl', 8309848), (8309844, 'b', 8309996), (8309908, 'bmi', 8309976), (8310124, 'b', 8310420), (8310180, 'bpl', 8310308), (8310236, 'b', 8310328), (8310324, 'b', 8310328), (8311208, 'bne', 8312416), (8311328, 'bmi', 8311388), (8311384, 'bpl', 8311828), (8311500, 'bpl', 8311540), (8311512, 'b', 8311688), (8311600, 'bmi', 8311668), (8311816, 'b', 8312052), (8311880, 'bpl', 8311944), (8311936, 'b', 8311964), (8311960, 'b', 8311964), (8312616, 'bne', 8312744), (8312744, 'b', 8312748)],
        semantics=('LoadWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:] @0x007ec070 (1538 words, 34 branches, 42 calls; [census] grade). Types @24@0:4@8^{WindowInfo=ffffffff}12@16@20. Frame: push {r4-r8,sl,fp,lr}; sub sp,sp,#0x378. Prologue builds the objc_super at fp-0x40 ({self, LoadWorldUI class object 0x00e911b0 via cell 0x007ecdec}) and calls through the objc_msgSendSuper2 GOT slot 0x007ecde4 (@selector(init), SEL cell 0x007ecde8) at 0x007ec0dc; a nil result returns immediately (beq 0x007ed7ac). Arg stores (all via pointer-to-offset-word ivar cells): self->delegate@4 = arg1 (str at 0x007ec15c), windowInfo@8 = arg2 (0x007ec170), cache@12 = arg3 (0x007ec184), cloudInterface@16 = arg4 (0x007ec198), state@40 = 0 (0x007ec1a4). Then 5 view-creation blocks, each = [class alloc] -> rect packed by the leaf helpers 0x007ed878 (10x) / 0x007ed8c4 (2x) (out[0..3] = x,y,w,h from r1,r2,r3,[sp]) -> initWithFrame:... -> immediate store into the ivar: (1) blockheadNamesTextView@28 = [[MJTextView alloc] (class cell 0x007ecdfc -> 0x00e90620) initWithFrame:<rect> cache:self->cache windowInfo:self->windowInfo string:"" (zero-length CFConstantString struct 0x00f917f8, cell 0x007ed40c) horizontalAlignment:1 font:[BitmapFont standardFont] (class cell 0x007ed2e8 -> 0x00e90c10, SEL 0x007ed2ec) color:{1,1,1,1} (four 0x3f800000 words packed into fp-0x60)] at 0x007ec474, stored 0x007ec488. (2) playButton@20 = [[MJButton alloc] initWithFrame:<rect> cache/winInfo title:@"PLAY" (0x00f91808, cell 0x007ed814)] (SEL 0x007ed820, 0x007eca08) + [cache textureNamed:@"InventoryButtonBackgroundGreen.png" (0x00f91818)] -> setBackgroundTexture: + ...SelectedGreen.png (0x00f91828) -> setBackgroundSelectedTexture: + setTarget:self action:@selector(playButton:) (SEL cells 0x007ed7f4/0x007ed7f8); store 0x007eca1c. (3) optionsButton@24 = same MJButton recipe with @"OPTIONS..." (0x00f91838, SEL 0x007ed834) and the non-green textures 0x00f91848/0x00f91858; store 0x007ed06c. (4) gdprStatus gate: int g = [[NSUserDefaults standardUserDefaults] integerForKey:@"gdprStatus"] (class cell 0x007ed830, SELs 0x007ed82c/0x007ed828, string 0x00f91868); internal helper 0x007ed910 returns (g==1||g==2); bne at 0x007ed1a8 jumps over the block when true. When false: disabledTextView@56 = [[MJTextView alloc] initWithFrame:... string:@"ONLINE PLAY DISABLED" (0x00f91878, cell 0x007ed858) alignment:1 font:[BitmapFont standardFont] color:white] then [self->disabledTextView setHidden:YES] (SEL cell 0x007ed850, sxtb\'d flag 1) - store 0x007ed634, setHidden 0x007ed65c. (5) hostUserName@152 = [[[NSUserDefaults standardUserDefaults] stringForKey:@"joinUserName" (0x00f91888, cell 0x007ed86c, SEL 0x007ed870)] retain (SEL cell 0x007ed868)]; if nil (cmp/bne 0x007ed728) it becomes [[self->delegate@4 defaultUserName] retain] (SEL cell 0x007ed874) - stores at 0x007ed70c/0x007ed7a0. Call histogram: 10 bl 0x7ed878 + 2 bl 0x7ed8c4 (rect/color packers), 1 bl 0x7ed910 (gdpr bool helper), 6 bl loc.imp.objc_msgSend, 24 blx rN (r3 x10, lr x6, ip x3, r2 x3, r6 x1 = the super-init). Branch skeleton: 1 beq (nil self), 10 bpl / 7 bmi (windowInfo float-compare layout switches re-used per block), 2 bne (gdpr + hostUserName), 14 b (tail trampolines/join points). All created views are stored via a saved &offset-word in a stack slot (e.g. playButton store: ldr r2,[sp,0x1a8]; ldr r3,[r2]; add r1,self,r3; str r0,[r1]). Class-ref words for SDK classes are 0 in the file (relocated at load), while in-binary classes (MJTextView 0x00e90620 / MJButton 0x00e92358 / BitmapFont 0x00e90c10) are pre-filled.'),
    ),
    dict(
        name='lwu_22',
        method='LoadWorldUI -[migrateToCustomButton:]',
        types='v12@0:4@8',
        start=8386768,
        end=8387824,
        disasm='disasm_worldtileloader_lwu_22.txt',
        base_add=8386784,
        base_literal=8387820,
        boundary='ARM.exidx end 0x007ffcf0 (listing bound); next ObjC IMP 0x007fff48 LoadWorldUI -[hostMultiLANButton:]',
        selectors={
                 0x7ffc94: (15211376, 'show'),
                 0x7ffc9c: (15211372, 'setDestructiveButtonWithTitle:block:'),
                 0x7ffca0: (17113136, 'ELF'),
                 0x7ffcb4: (15211364, 'setCancelButtonWithTitle:block:'),
                 0x7ffcb8: (17113104, 'ELF'),
                 0x7ffcc4: (15211360, 'initWithTitle:message:'),
                 0x7ffcc8: (15211348, 'uppercaseString'),
                 0x7ffccc: (15211120, 'alloc'),
                 0x7ffcd8: (15211228, 'stringWithFormat:'),
                 0x7ffce0: (15211224, 'objectForKey:'),
        },
        imports={
                 0x7ffc90: (17151904, 'objc_msgSend'),
                 0x7ffc98: (16325368, '__CFConstantStringClassReference'),
                 0x7ffcac: (17151928, '_NSConcreteStackBlock'),
                 0x7ffcb0: (16325416, '__CFConstantStringClassReference'),
                 0x7ffcc0: (16325528, '__CFConstantStringClassReference'),
                 0x7ffcd4: (16325512, '__CFConstantStringClassReference'),
                 0x7ffcdc: (16325336, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7ffc8c: (17160936, 'OBJC_IVAR_$_LoadWorldUI.deleteAlertView', 60),
                 0x7ffce4: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
        },
        classes={
                 0x7ffcd0: (15247272, 'OBJC_CLASS_$_BlockAlertView'),
                 0x7ffce8: (15247248, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(8386768, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8387820, 'addeq r0, r6, ip, lsl 4')],
        calls=[(8387312, 'blx r3'), (8387328, 'blx r2'), (8387364, 'blx ip'), (8387400, 'blx r3'), (8387432, 'blx r3'), (8387468, 'blx ip'), (8387580, 'blx r5'), (8387676, 'blx r5'), (8387712, 'blx r3')],
        branches=[(8386836, 'bne', 8387716)],
        semantics=('LoadWorldUI -[migrateToCustomButton:] @0x007ff8d0 (264 words, 1 branch, 9 calls): confirmation alert for the one-way "migrate world to custom rules" action; built on the same template as lwu_24 but stored in self->deleteAlertView@60 (cell 0x007ffc8c) and guarded by that ivar (if non-nil -> return at once, bne). Sends: (1) worldName = [self->gameSave@36 objectForKey:@"worldName"] (const 0x00f91ad8, SEL cell 0x007ffce0) -> (2) [worldName uppercaseString] -> (3) msg = [NSString stringWithFormat: FMT, upperWorldName] (SEL 0x007ffcd8) with FMT 0x00f91b88 (242 chars) = "Would you like to migrate %@ to custom rules?\\n\\nENABLING CUSTOM RULES GIVES MORE ADVANCED WORLD OPTIONS. HOWEVER YOU CAN NO LONGER MINE TIME CRYSTALS OR USE PORTAL CHESTS IN THIS WORLD.\\n\\nTHIS IS A ONE WAY MIGRATION SO IT CAN\'T BE CHANGED BACK!" -> (4) [BlockAlertView alloc] -> (5) [msg uppercaseString] -> (6) [alert initWithTitle:@"MIGRATE WORLD?" (0x00f91b98) message:upperMsg] -> stored into self->deleteAlertView -> (7) [alert setCancelButtonWithTitle:@"CANCEL" block:<stack block1 @fp-0x40>] -> (8) [alert setDestructiveButtonWithTitle:@"MIGRATE TO CUSTOM RULES" (0x00f91af8) block:<stack block2 @fp-0x58>] -> (9) [self->deleteAlertView show]. Blocks: {isa=_NSConcreteStackBlock, flags=0xC2000000, 0, invoke, descriptor, self}; block1 (cancel) invoke 0x007ffcf0, descriptor 0x01052010 (copy 0x007ffd8c / dispose 0x007ffdcc): [self->deleteAlertView autorelease] then deleteAlertView=nil. Block2 (destructive) invoke 0x007ffdf4, descriptor 0x01052030 (copy 0x007ffee0 / dispose 0x007fff20): the same autorelease+nil plus [self->delegate@4 migrateCurrentWorldToCustomRules] (SEL 0xe81b78, addr via cell 0x007ffecc). Base T=pc+0x86020c=0x0105faf4.'),
    ),
    dict(
        name='lwu_23',
        method='LoadWorldUI -[moveTouch:]',
        types='v16@0:4{CGPoint=ff}8',
        start=8406576,
        end=8408184,
        disasm='disasm_worldtileloader_lwu_23.txt',
        base_add=8406592,
        base_literal=8408180,
        boundary='ARM.exidx end 0x008052c0; body trimmed at the next IMP 0x00804c78 LoadWorldUI -[endTouch:]',
        selectors={
                 0x804c28: (15211416, 'moveTouch:'),
        },
        imports={},
        ivars={
                 0x804c1c: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x804c20: (17160992, 'OBJC_IVAR_$_LoadWorldUI.backButton', 48),
                 0x804c2c: (17160960, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameButton', 104),
                 0x804c30: (17160952, 'OBJC_IVAR_$_LoadWorldUI.hostPicButton', 112),
                 0x804c34: (17160944, 'OBJC_IVAR_$_LoadWorldUI.hostPvpButton', 120),
                 0x804c38: (17160940, 'OBJC_IVAR_$_LoadWorldUI.hostNowButton', 124),
                 0x804c40: (17160968, 'OBJC_IVAR_$_LoadWorldUI.hostMultiLANButton', 96),
                 0x804c48: (17160988, 'OBJC_IVAR_$_LoadWorldUI.deleteWorldButton', 52),
                 0x804c4c: (17161020, 'OBJC_IVAR_$_LoadWorldUI.onlinePicButton', 132),
                 0x804c50: (17161024, 'OBJC_IVAR_$_LoadWorldUI.onlineShareButton', 136),
                 0x804c54: (17161028, 'OBJC_IVAR_$_LoadWorldUI.onlineOwnerPortalButton', 140),
                 0x804c5c: (17160980, 'OBJC_IVAR_$_LoadWorldUI.worldNameButton', 84),
                 0x804c60: (17160976, 'OBJC_IVAR_$_LoadWorldUI.hostMultiButton', 88),
                 0x804c64: (17160972, 'OBJC_IVAR_$_LoadWorldUI.migrateToCustomButton', 92),
                 0x804c68: (17160912, 'OBJC_IVAR_$_LoadWorldUI.playButton', 20),
                 0x804c70: (17160916, 'OBJC_IVAR_$_LoadWorldUI.optionsButton', 24),
        },
        classes={},
        instructions=[(8406576, 'push {fp, lr}'), (8408180, 'addeq fp, r5, ip, lsr 9')],
        calls=[(8406728, 'bl loc.imp.objc_msgSend'), (8406788, 'bl loc.imp.objc_msgSend'), (8406912, 'bl loc.imp.objc_msgSend'), (8406972, 'bl loc.imp.objc_msgSend'), (8407032, 'bl loc.imp.objc_msgSend'), (8407092, 'bl loc.imp.objc_msgSend'), (8407152, 'bl loc.imp.objc_msgSend'), (8407276, 'bl loc.imp.objc_msgSend'), (8407336, 'bl loc.imp.objc_msgSend'), (8407396, 'bl loc.imp.objc_msgSend'), (8407456, 'bl loc.imp.objc_msgSend'), (8407516, 'bl loc.imp.objc_msgSend'), (8407640, 'bl loc.imp.objc_msgSend'), (8407700, 'bl loc.imp.objc_msgSend'), (8407824, 'bl loc.imp.objc_msgSend'), (8407884, 'bl loc.imp.objc_msgSend'), (8407944, 'bl loc.imp.objc_msgSend'), (8408004, 'bl loc.imp.objc_msgSend'), (8408064, 'bl loc.imp.objc_msgSend')],
        branches=[(8406644, 'bne', 8406796), (8406792, 'b', 8408084), (8406828, 'bne', 8407160), (8407156, 'b', 8408080), (8407192, 'bne', 8407524), (8407520, 'b', 8408076), (8407556, 'bne', 8407708), (8407704, 'b', 8408072), (8407740, 'bne', 8408068), (8408068, 'b', 8408072), (8408072, 'b', 8408076), (8408076, 'b', 8408080), (8408080, 'b', 8408084)],
        semantics=('LoadWorldUI -[moveTouch:] @@0x00804630 (402 words, 13 branches, 19 calls; [census-lite]): state-machine touch router. Reads OBJC_IVAR_$_LoadWorldUI.state@40 (cell 0x00804c1c) and forwards the CGPoint argument ((x,y) = (r2,r3) spilled to [fp,-8]/[fp,-4]) with @selector(moveTouch:) (SEL cell 0x00804c28) to the buttons of the current page only - one bl loc.imp.objc_msgSend per ivar, each receiver addressed through its own offset cell: state 0: playButton@20 (cell 0x00804c68), optionsButton@24 (0x00804c70); state 1: backButton@48 (0x00804c20), deleteWorldButton@52 (0x00804c48), worldNameButton@84 (0x00804c5c), hostMultiButton@88 (0x00804c60), migrateToCustomButton@92 (0x00804c64); state 2: backButton@48, deleteWorldButton@52, onlinePicButton@132 (0x00804c4c), onlineShareButton@136 (0x00804c50), onlineOwnerPortalButton@140 (0x00804c54); state 3: backButton@48, hostMultiLANButton@96 (0x00804c40); state 4: backButton@48, hostNickNameButton@104 (0x00804c2c), hostPicButton@112 (0x00804c30), hostPvpButton@120 (0x00804c34), hostNowButton@124 (0x00804c38). Any other state value falls through the bne chain to the epilogue (no sends). All sends are to possibly-nil ivars (safe no-ops when the button is absent). Base T=pc+0x85b4ac=0x0105faf4. Roster boundary note: the listing header carries ARM.exidx end 0x008052c0 (which is endTouch:\'s end) but the body is trimmed at the next IMP 0x00804c78 -[endTouch:]; the listing indeed contains only moveTouch rows (last row 0x00804c58, then pool) - no endTouch rows leak in (checked: 0 shared addresses with lwu_09).'),
    ),
    dict(
        name='lwu_24',
        method='LoadWorldUI -[onlineOwnerPortalButton:]',
        types='v12@0:4@8',
        start=8419868,
        end=8420792,
        disasm='disasm_worldtileloader_lwu_24.txt',
        base_add=8419884,
        base_literal=8420788,
        boundary='ARM.exidx end 0x00807db8 (listing bound); next ObjC IMP 0x00808088 LoadWorldUI -[onlineShareButton:]',
        selectors={
                 0x807d68: (15211376, 'show'),
                 0x807d70: (15211584, 'addButtonWithTitle:block:'),
                 0x807d74: (17113200, 'ELF'),
                 0x807d88: (15211364, 'setCancelButtonWithTitle:block:'),
                 0x807d8c: (17113168, 'ELF'),
                 0x807d98: (15211360, 'initWithTitle:message:'),
                 0x807d9c: (15211348, 'uppercaseString'),
                 0x807da0: (15211120, 'alloc'),
                 0x807dac: (15211228, 'stringWithFormat:'),
        },
        imports={
                 0x807d64: (17151904, 'objc_msgSend'),
                 0x807d6c: (16325736, '__CFConstantStringClassReference'),
                 0x807d80: (17151928, '_NSConcreteStackBlock'),
                 0x807d84: (16325416, '__CFConstantStringClassReference'),
                 0x807d94: (16325720, '__CFConstantStringClassReference'),
                 0x807da8: (16325704, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x807d60: (17160928, 'OBJC_IVAR_$_LoadWorldUI.portalAlertView', 72),
        },
        classes={
                 0x807da4: (15247272, 'OBJC_CLASS_$_BlockAlertView'),
                 0x807db0: (15247248, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(8419868, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8420788, 'addeq r8, r5, r0, asr 1')],
        calls=[(8420344, 'blx r3'), (8420380, 'blx r3'), (8420412, 'blx r3'), (8420448, 'blx ip'), (8420560, 'blx r5'), (8420656, 'blx r5'), (8420692, 'blx r3')],
        branches=[(8419936, 'bne', 8420696)],
        semantics=('LoadWorldUI -[onlineOwnerPortalButton:] @0x00807a1c (231 words, 1 branch, 7 calls): builds and shows the OWNER PORTAL info alert. Guard: if self->portalAlertView@72 != nil it returns immediately (bne to epilogue). Then 7 sends: (1) +[NSString stringWithFormat:] on the class object (NSString class cell 0x00807db0, SEL cell 0x00807dac) with format string 0x00f91c48 = "The owner portal is a web site where you can monitor worlds, manage settings, and even chat in worlds you own. All from outside the game!" (137 chars) -> (2) [BlockAlertView alloc] (class cell 0x00807da4) -> (3) [thatString uppercaseString] -> (4) [alert initWithTitle:@"OWNER PORTAL" (0x00f91c58) message:<uppercased text> (SEL cell 0x00807d98)] -> result stored to self->portalAlertView@72 -> (5) [alert setCancelButtonWithTitle:@"CANCEL" (0x00f91b28) block:<stack block1>] (SEL cell 0x00807d88) -> (6) [alert addButtonWithTitle:@"VISIT PORTAL" (0x00f91c68) block:<stack block2>] (SEL cell 0x00807d70) -> (7) [self->portalAlertView show] (SEL cell 0x00807d68). Both blocks are hand-built stack blocks {isa=_NSConcreteStackBlock (cell 0x00807d80), flags=0xC2000000, reserved=0, invoke_fn, descriptor, captured self}: the 0xc2000000 literal at cell 0x00807d7c looks like the float -32.0f but is block flags (HAS_COPY_DISPOSE|HAS_SIGNATURE|HAS_EXTENDED_LAYOUT); descriptors at 0x01052050 (block2) / 0x01052070 (block1), size 0x18, copy 0x00808020, dispose 0x00808060. Block1 invoke F1 @0x00807db8 (CANCEL action): [self->portalAlertView autorelease] then self->portalAlertView=nil (ARC strong-store-to-nil). Block2 invoke F2 @0x00807ebc (VISIT PORTAL action): [self->cloudInterface@16 openOwnerPortalWithUserName:[self->gameSave@36 objectForKey:@"userName"]] (SEL cells 0x00808008/0x00808010, const 0x00f91918) then the same autorelease+nil. Base T=pc+0x8580c0=0x0105faf4.'),
    ),
    dict(
        name='lwu_25',
        method='LoadWorldUI -[onlinePicButton:]',
        types='v12@0:4@8',
        start=8415540,
        end=8415892,
        disasm='disasm_worldtileloader_lwu_25.txt',
        base_add=8415556,
        base_literal=8415888,
        boundary='ARM.exidx end 0x00806a94 (listing bound); next ObjC IMP 0x00806ac0 LoadWorldUI -[hostPicButton:]',
        selectors={
                 0x806a7c: (15211524, 'frame'),
                 0x806a8c: (15211528, 'startImagePickerWithDelegate:forRect:cropSize:'),
        },
        imports={},
        ivars={
                 0x806a80: (17161048, 'OBJC_IVAR_$_LoadWorldUI.avatarPickButton', 164),
                 0x806a84: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
        },
        classes={},
        instructions=[(8415540, 'push {r4, r5, fp, lr}'), (8415888, 'addeq sb, r5, r8, lsr 3')],
        calls=[(8415648, 'bl loc.imp.objc_msgSend_stret'), (8415684, 'bl sym.imp.memset'), (8415784, 'bl 0x806a94'), (8415856, 'bl loc.imp.objc_msgSend')],
        branches=[(8415632, 'beq', 8415656), (8415652, 'b', 8415688)],
        semantics=('LoadWorldUI -[onlinePicButton:] @0x00806934 (88 words, 2 branches, 4 calls): avatar-picture picker entry; stores the tapped button into self->avatarPickButton@164 (ivar cell 0x00806a80), then captures the sender button\'s frame: sender != nil (cmp against a movw-zero) -> bl loc.imp.objc_msgSend_stret 0x008069a0 with out=&[fp-0x28], receiver=sender, SEL=@selector(frame) (cell 0x00806a7c); sender == nil -> movw r2,#0x10 + bl sym.imp.memset zeros the same 16 bytes (fill value forced with and r1,r1,#0xff). Then bl 0x00806a94 - a leaf CGSize packer (sub sp,#8; vmov s0,r2 / s2,r1; spills both; writes w=r1 to [r0] and h=r2 to [r0,#4]) - fills [sp,0x30] with cropSize {320.0f,320.0f} (movw/movt 0x43a00000, passed in r1=r2=ip). Final send via loc.imp.objc_msgSend 0x00806a70: receiver self->delegate@4 (cell 0x00806a84), SEL startImagePickerWithDelegate:forRect:cropSize: (cell 0x00806a8c), arg1=self, forRect: the captured sender CGRect (r3/[sp]/[sp+4]/[sp+8]), cropSize: 320x320 ([sp+0xc]/[sp+0x10]). Base T=pc+0x8591a8=0x0105faf4. Byte-identical twin of lwu_14 (hostPicButton:) - verified by a mnemonic/operand diff modulo pool constants (82/82 rows).'),
    ),
    dict(
        name='lwu_26',
        method='LoadWorldUI -[onlineShareButton:]',
        types='v12@0:4@8',
        start=8421512,
        end=8423208,
        disasm='disasm_worldtileloader_lwu_26.txt',
        base_add=8421528,
        base_literal=8423204,
        boundary='ARM.exidx end 0x00808728 (listing bound); next ObjC IMP 0x00808728 LoadWorldUI -[hostUserName]',
        selectors={
                 0x8086bc: (15211252, 'boolValue'),
                 0x8086c4: (15211224, 'objectForKey:'),
                 0x8086d0: (15211228, 'stringWithFormat:'),
                 0x8086d4: (15211480, 'stringByAddingPercentEscapesUsingEncoding:'),
                 0x8086f0: (15211376, 'show'),
                 0x8086f8: (15211440, 'setText:'),
                 0x8086fc: (15211444, 'textFieldAtIndex:'),
                 0x808700: (15211504, 'setAlertViewStyle:'),
                 0x808714: (15211500, 'initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:'),
                 0x808718: (15211120, 'alloc'),
        },
        imports={
                 0x8086b8: (17151904, 'objc_msgSend'),
                 0x8086c0: (16325160, '__CFConstantStringClassReference'),
                 0x8086cc: (16325768, '__CFConstantStringClassReference'),
                 0x8086d8: (16325336, '__CFConstantStringClassReference'),
                 0x8086dc: (16325800, '__CFConstantStringClassReference'),
                 0x8086e0: (16325784, '__CFConstantStringClassReference'),
                 0x8086e8: (16325752, '__CFConstantStringClassReference'),
                 0x8086ec: (16324808, '__CFConstantStringClassReference'),
                 0x808704: (16325832, '__CFConstantStringClassReference'),
                 0x808708: (16325656, '__CFConstantStringClassReference'),
                 0x80870c: (16325848, '__CFConstantStringClassReference'),
                 0x808710: (16325864, '__CFConstantStringClassReference'),
                 0x808720: (16325816, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8086c8: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
                 0x8086f4: (17161040, 'OBJC_IVAR_$_LoadWorldUI.shareTextAlertView', 76),
        },
        classes={
                 0x8086e4: (15247248, 'OBJC_CLASS_$_NSString'),
                 0x80871c: (15247300, 'OBJC_CLASS_$_UIAlertView'),
        },
        instructions=[(8421512, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8423204, 'addeq r7, r5, r4, asr sl')],
        calls=[(8421632, 'blx ip'), (8421648, 'blx r2'), (8421848, 'blx sl'), (8421900, 'blx ip'), (8421920, 'blx r3'), (8421964, 'blx lr'), (8422164, 'blx r3'), (8422184, 'blx r3'), (8422236, 'blx ip'), (8422288, 'blx ip'), (8422308, 'blx r3'), (8422360, 'blx r4'), (8422776, 'blx r3'), (8422812, 'blx ip'), (8422848, 'blx r3'), (8422924, 'blx r7'), (8422980, 'blx r3'), (8423020, 'blx r3'), (8423048, 'blx r3'), (8423084, 'blx r3')],
        branches=[(8421660, 'beq', 8421976), (8421972, 'b', 8422368)],
        semantics=('LoadWorldUI -[onlineShareButton:] @0x00808088 (424 words, 20 calls, 2 branches; census-lite) - the world-card \'Share\' button handler: it builds a theblockheads.net join link for the current world and presents it in a UIAlertView with Copy / E-mail buttons. PIC base 0x0105faf4 (pool cell 0x00808724 = 0x857a54 + pc 0x008080a0); objc_msgSend cached from GOT 0x0105b7a0. Send sequence (20 sends, 6 of them after the branch converge): (1-2) 0x00808100/0x00808110 cloudFlag = [[self->gameSave@36 objectForKey:@"cloudGame" (CFSTR 0x00f91a28)] boolValue] -> \'sxtb r0,r0; cmp r0,0; beq 0x00808258\' selects the branch; (3-6) cloud branch (fall-through 0x00808120..0x00808254): [gameSave objectForKey:@"saveID" (0x00f918c8)], [gameSave objectForKey:@"worldName" (0x00f91ad8)], [worldName stringByAddingPercentEscapesUsingEncoding:4], then [NSString stringWithFormat:@"http://theblockheads.net/join.php?id=%@&name=%@" (0x00f91c78), rawSaveID, escapedWorldName] (3rd format arg passed on the stack); (7-12) LAN branch (0x00808258..0x008083d8): [gameSave objectForKey:@"host" (0x00f91c98)] -> stringByAddingPercentEscapesUsingEncoding:4, [gameSave objectForKey:@"port" (0x00f91ca8)], [gameSave objectForKey:@"worldName"], escape(4), then [NSString stringWithFormat:@"http://theblockheads.net/join.php?ip=%@&port=%@&name=%@" (0x00f91c88), escapedHost, rawPort, escapedWorldName] (varargs on the stack at [sp]/[sp,4]); (13-20) shared tail 0x008083e0..0x008086b4, with all constants pre-loaded into r2/r3/r4/r5/r6/r7/r8/sl/ip/lr and then spilled into a cookie table at [sp,0x1c..0x8c] and reloaded per call: [self->gameSave objectForKey:@"worldName"] -> title = [NSString stringWithFormat:@"Link to join %@" (0x00f91cb8), name]; alert = [UIAlertView alloc (class 0x00e8a7c4)]; [alert initWithTitle:title message:@"Copy this link, and use it from any iOS or Android device that has The Blockheads" (0x00f91cc8) delegate:self (self spilled to [sp]) cancelButtonTitle:@"Cancel" (0x00f91c18) otherButtonTitles:@"Copy" (0x00f91cd8), @"E-mail" (0x00f91ce8), nil]; the result is stored straight into the ivar slot with \'ldr r0,[self]; str r0,[self+76]\' = self->shareTextAlertView@76 (ivar cell 0x008086f4 -> GOT 0x0105db50); [self->shareTextAlertView setAlertViewStyle:2] (movw r8,#2); [[self->shareTextAlertView textFieldAtIndex:0] setText:link]; [self->shareTextAlertView show] (selref 0x00e81b70). Every receiver is reloaded from the ivar cell (shareTextAlertView@76 re-read 5x through [sp,0x2c]), which is why the same selector appears in several windows.'),
    ),
    dict(
        name='lwu_27',
        method='LoadWorldUI -[optionsButton:]',
        types='v12@0:4@8',
        start=8361196,
        end=8381852,
        disasm='disasm_worldtileloader_lwu_27.txt',
        base_add=8361216,
        base_literal=8365232,
        boundary='ARM.exidx end 0x007fe59c (listing bound); next ObjC IMP 0x007fe59c LoadWorldUI -[backButton:]',
        selectors={
                 0x7fa4c0: (15211120, 'alloc'),
                 0x7fa570: (15211120, 'alloc'),
                 0x7fa578: (15211152, 'setTarget:action:'),
                 0x7fa57c: (15211324, 'backButton:'),
                 0x7fa580: (15211144, 'setBackgroundSelectedTexture:'),
                 0x7fa588: (15211136, 'textureNamed:'),
                 0x7fa590: (15211140, 'setBackgroundTexture:'),
                 0x7fa8a0: (15211132, 'initWithFrame:cache:windowInfo:title:'),
                 0x7fac90: (15211328, 'deleteWorldButton:'),
                 0x7facac: (15211252, 'boolValue'),
                 0x7facb4: (15211224, 'objectForKey:'),
                 0x7facd8: (15211256, 'setTitle:'),
                 0x7fb508: (15211332, 'onlineOwnerPortalButton:'),
                 0x7fb860: (15211196, 'release'),
                 0x7fbba4: (15211336, 'onlineShareButton:'),
                 0x7fc524: (15211124, 'standardFont'),
                 0x7fc610: (15211128, 'initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:'),
                 0x7fcc1c: (15211212, 'setFrame:'),
                 0x7fcc2c: (15211120, 'alloc'),
                 0x7fd164: (15211144, 'setBackgroundSelectedTexture:'),
                 0x7fd16c: (15211136, 'textureNamed:'),
                 0x7fd210: (15211136, 'textureNamed:'),
                 0x7fd214: (15211140, 'setBackgroundTexture:'),
                 0x7fd220: (15211132, 'initWithFrame:cache:windowInfo:title:'),
                 0x7fd22c: (15211220, 'setGlyphTexture:'),
                 0x7fd230: (15211344, 'setTitleAlignment:'),
                 0x7fd234: (15211152, 'setTarget:action:'),
                 0x7fd238: (15211340, 'onlinePicButton:'),
                 0x7fda70: (15211256, 'setTitle:'),
                 0x7fe224: (15211352, 'worldNameButton:'),
                 0x7fe3b8: (15211224, 'objectForKey:'),
                 0x7fe3c0: (15211348, 'uppercaseString'),
                 0x7fe518: (15211120, 'alloc'),
                 0x7fe52c: (15211152, 'setTarget:action:'),
                 0x7fe530: (15211144, 'setBackgroundSelectedTexture:'),
                 0x7fe534: (15211136, 'textureNamed:'),
                 0x7fe53c: (15211140, 'setBackgroundTexture:'),
                 0x7fe540: (15211132, 'initWithFrame:cache:windowInfo:title:'),
                 0x7fe554: (15211224, 'objectForKey:'),
                 0x7fe55c: (15211256, 'setTitle:'),
                 0x7fe560: (15211212, 'setFrame:'),
                 0x7fe568: (15211348, 'uppercaseString'),
                 0x7fe57c: (15211356, 'migrateToCustomButton:'),
                 0x7fe594: (15211188, 'autorelease'),
        },
        imports={
                 0x7fa4bc: (17151904, 'objc_msgSend'),
                 0x7fa56c: (17151904, 'objc_msgSend'),
                 0x7fa584: (16324696, '__CFConstantStringClassReference'),
                 0x7fa594: (16324680, '__CFConstantStringClassReference'),
                 0x7fa8a4: (16325176, '__CFConstantStringClassReference'),
                 0x7fac98: (16325224, '__CFConstantStringClassReference'),
                 0x7fac9c: (16325208, '__CFConstantStringClassReference'),
                 0x7faca4: (16325192, '__CFConstantStringClassReference'),
                 0x7facb0: (16324856, '__CFConstantStringClassReference'),
                 0x7facd0: (16325160, '__CFConstantStringClassReference'),
                 0x7facd4: (16325240, '__CFConstantStringClassReference'),
                 0x7fb1c4: (16325256, '__CFConstantStringClassReference'),
                 0x7fb6bc: (16325272, '__CFConstantStringClassReference'),
                 0x7fbe58: (16325288, '__CFConstantStringClassReference'),
                 0x7fc614: (16325304, '__CFConstantStringClassReference'),
                 0x7fcc28: (17151904, 'objc_msgSend'),
                 0x7fd168: (16324696, '__CFConstantStringClassReference'),
                 0x7fd218: (16324680, '__CFConstantStringClassReference'),
                 0x7fd224: (16324600, '__CFConstantStringClassReference'),
                 0x7fda6c: (16325192, '__CFConstantStringClassReference'),
                 0x7fde00: (16325320, '__CFConstantStringClassReference'),
                 0x7fe228: (16325352, '__CFConstantStringClassReference'),
                 0x7fe3bc: (16325336, '__CFConstantStringClassReference'),
                 0x7fe514: (17151904, 'objc_msgSend'),
                 0x7fe54c: (16325224, '__CFConstantStringClassReference'),
                 0x7fe550: (16325208, '__CFConstantStringClassReference'),
                 0x7fe564: (16325336, '__CFConstantStringClassReference'),
                 0x7fe578: (16324920, '__CFConstantStringClassReference'),
                 0x7fe584: (16325368, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7fa4b4: (17160992, 'OBJC_IVAR_$_LoadWorldUI.backButton', 48),
                 0x7fa4b8: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7fa568: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7fa58c: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
                 0x7fac94: (17160988, 'OBJC_IVAR_$_LoadWorldUI.deleteWorldButton', 52),
                 0x7facb8: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
                 0x7fb110: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x7fb240: (17161016, 'OBJC_IVAR_$_LoadWorldUI.onlinePlayerIsOwner', 144),
                 0x7fb50c: (17161028, 'OBJC_IVAR_$_LoadWorldUI.onlineOwnerPortalButton', 140),
                 0x7fb8dc: (17161024, 'OBJC_IVAR_$_LoadWorldUI.onlineShareButton', 136),
                 0x7fb954: (17161024, 'OBJC_IVAR_$_LoadWorldUI.onlineShareButton', 136),
                 0x7fbf34: (17161012, 'OBJC_IVAR_$_LoadWorldUI.onlinePicTextView', 128),
                 0x7fbfe8: (17161012, 'OBJC_IVAR_$_LoadWorldUI.onlinePicTextView', 128),
                 0x7fc514: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
                 0x7fc51c: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7fcc24: (17161020, 'OBJC_IVAR_$_LoadWorldUI.onlinePicButton', 132),
                 0x7fd160: (17161000, 'OBJC_IVAR_$_LoadWorldUI.picTexture', 148),
                 0x7fd52c: (17161016, 'OBJC_IVAR_$_LoadWorldUI.onlinePlayerIsOwner', 144),
                 0x7fda68: (17160984, 'OBJC_IVAR_$_LoadWorldUI.worldNameTextView', 80),
                 0x7fda74: (17160988, 'OBJC_IVAR_$_LoadWorldUI.deleteWorldButton', 52),
                 0x7fda78: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x7fdeac: (17160980, 'OBJC_IVAR_$_LoadWorldUI.worldNameButton', 84),
                 0x7fe3b4: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
                 0x7fe510: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7fe538: (17160900, 'OBJC_IVAR_$_LoadWorldUI.cache', 12),
                 0x7fe548: (17160988, 'OBJC_IVAR_$_LoadWorldUI.deleteWorldButton', 52),
                 0x7fe558: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
                 0x7fe570: (17160976, 'OBJC_IVAR_$_LoadWorldUI.hostMultiButton', 88),
                 0x7fe574: (17160920, 'OBJC_IVAR_$_LoadWorldUI.disabledTextView', 56),
                 0x7fe580: (17160972, 'OBJC_IVAR_$_LoadWorldUI.migrateToCustomButton', 92),
        },
        classes={
                 0x7fa4c4: (15247240, 'OBJC_CLASS_$_MJButton'),
                 0x7fa574: (15247240, 'OBJC_CLASS_$_MJButton'),
                 0x7fbfec: (15247232, 'OBJC_CLASS_$_MJTextView'),
                 0x7fc520: (15247236, 'OBJC_CLASS_$_BitmapFont'),
                 0x7fcc30: (15247240, 'OBJC_CLASS_$_MJButton'),
                 0x7fccd4: (15247240, 'OBJC_CLASS_$_MJButton'),
                 0x7fe51c: (15247240, 'OBJC_CLASS_$_MJButton'),
        },
        instructions=[(8361196, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8381848, 'ldrdeq r1, r2, [r6], r0')],
        calls=[(8361344, 'blx r3'), (8361648, 'bl 0x7ed878'), (8361892, 'bl 0x7ed878'), (8362344, 'bl loc.imp.objc_msgSend'), (8362432, 'blx lr'), (8362464, 'blx r3'), (8362532, 'blx lr'), (8362564, 'blx r3'), (8362612, 'blx lr'), (8362644, 'blx r3'), (8363068, 'bl 0x7ed878'), (8363464, 'bl 0x7ed878'), (8363836, 'bl loc.imp.objc_msgSend'), (8363924, 'blx lr'), (8363956, 'blx r3'), (8364024, 'blx lr'), (8364056, 'blx r3'), (8364104, 'blx lr'), (8364200, 'blx ip'), (8364216, 'blx r2'), (8364396, 'blx r6'), (8364436, 'blx r3'), (8364452, 'blx r2'), (8364560, 'blx ip'), (8364576, 'blx r2'), (8364692, 'blx r3'), (8365112, 'bl 0x7ed878'), (8365592, 'bl 0x7ed878'), (8365964, 'bl loc.imp.objc_msgSend'), (8366052, 'blx lr'), (8366084, 'blx r3'), (8366152, 'blx lr'), (8366184, 'blx r3'), (8366232, 'blx lr'), (8366348, 'blx r3'), (8366488, 'blx r3'), (8366948, 'bl 0x7ed878'), (8367436, 'bl 0x7ed878'), (8367808, 'bl loc.imp.objc_msgSend'), (8367896, 'blx lr'), (8367928, 'blx r3'), (8367996, 'blx lr'), (8368028, 'blx r3'), (8368076, 'blx lr'), (8368196, 'blx r3'), (8368696, 'bl 0x7ed878'), (8369112, 'bl 0x7ed878'), (8369556, 'bl 0x7ed878'), (8369652, 'bl loc.imp.objc_msgSend'), (8369692, 'bl 0x7ed8c4'), (8369824, 'bl loc.imp.objc_msgSend'), (8370388, 'bl 0x7ed878'), (8370808, 'bl 0x7ed878'), (8371236, 'bl 0x7ed878'), (8371288, 'bl loc.imp.objc_msgSend'), (8371408, 'blx r3'), (8371896, 'bl 0x7ed878'), (8372292, 'bl 0x7ed878'), (8372688, 'bl 0x7ed878'), (8373012, 'bl loc.imp.objc_msgSend'), (8373100, 'blx lr'), (8373132, 'blx r3'), (8373200, 'blx lr'), (8373232, 'blx r3'), (8373356, 'blx r3'), (8373476, 'blx r4'), (8373516, 'blx r3'), (8374024, 'bl 0x7ed878'), (8374376, 'bl 0x7ed878'), (8374744, 'bl 0x7ed878'), (8374860, 'bl loc.imp.objc_msgSend'), (8374916, 'blx lr'), (8375044, 'blx ip'), (8375160, 'blx ip'), (8375612, 'bl 0x7ed878'), (8375696, 'bl loc.imp.objc_msgSend'), (8375736, 'bl 0x7ed8c4'), (8375868, 'bl loc.imp.objc_msgSend'), (8376332, 'bl 0x7ed878'), (8376384, 'bl loc.imp.objc_msgSend'), (8376508, 'blx ip'), (8377252, 'bl 0x7ed878'), (8377336, 'bl loc.imp.objc_msgSend'), (8377352, 'bl loc.imp.objc_msgSend'), (8377428, 'bl loc.imp.objc_msgSend'), (8377516, 'blx lr'), (8377548, 'blx r3'), (8377596, 'blx lr'), (8377636, 'blx r3'), (8377844, 'blx lr'), (8377860, 'blx r2'), (8377892, 'blx r3'), (8378396, 'bl 0x7ed878'), (8378444, 'bl loc.imp.objc_msgSend'), (8378612, 'blx r3'), (8378776, 'blx r4'), (8379284, 'bl 0x7ed878'), (8379664, 'bl 0x7ed878'), (8379716, 'bl loc.imp.objc_msgSend'), (8379800, 'blx r3'), (8380384, 'bl 0x7ed878'), (8380516, 'bl loc.imp.objc_msgSend'), (8380604, 'blx lr'), (8380636, 'blx r3'), (8380704, 'blx lr'), (8380736, 'blx r3'), (8380784, 'blx lr'), (8381240, 'bl 0x7ed878'), (8381640, 'bl 0x7ed878'), (8381692, 'bl loc.imp.objc_msgSend')],
        branches=[(8361268, 'bne', 8364108), (8361388, 'bpl', 8361656), (8361444, 'bpl', 8361504), (8361500, 'b', 8361524), (8361520, 'b', 8361524), (8361652, 'b', 8361896), (8361708, 'bpl', 8361784), (8361764, 'b', 8361804), (8361800, 'b', 8361804), (8362688, 'bpl', 8363076), (8362744, 'bpl', 8362808), (8362800, 'b', 8362828), (8362824, 'b', 8362828), (8362888, 'bpl', 8362968), (8362964, 'b', 8362988), (8362984, 'b', 8362988), (8363072, 'b', 8363468), (8363128, 'bpl', 8363188), (8363184, 'b', 8363208), (8363204, 'b', 8363208), (8363268, 'bpl', 8363364), (8363344, 'b', 8363384), (8363380, 'b', 8363384), (8364228, 'beq', 8374928), (8364464, 'beq', 8366252), (8364588, 'bne', 8366252), (8364736, 'bpl', 8365120), (8364792, 'bpl', 8364852), (8364848, 'b', 8364872), (8364868, 'b', 8364872), (8364932, 'bpl', 8365012), (8365008, 'b', 8365032), (8365028, 'b', 8365032), (8365116, 'b', 8365596), (8365172, 'bpl', 8365256), (8365228, 'b', 8365276), (8365272, 'b', 8365276), (8365336, 'bpl', 8365488), (8365412, 'b', 8365508), (8365504, 'b', 8365508), (8366236, 'b', 8366376), (8366412, 'bne', 8368080), (8366532, 'bpl', 8366956), (8366568, 'beq', 8366956), (8366624, 'bpl', 8366688), (8366684, 'b', 8366712), (8366708, 'b', 8366712), (8366780, 'bpl', 8366864), (8366860, 'b', 8366888), (8366884, 'b', 8366888), (8366952, 'b', 8367440), (8367008, 'bpl', 8367072), (8367068, 'b', 8367096), (8367092, 'b', 8367096), (8367164, 'bpl', 8367324), (8367244, 'b', 8367348), (8367344, 'b', 8367348), (8368116, 'bne', 8369860), (8368244, 'bpl', 8369120), (8368280, 'beq', 8368708), (8368336, 'bpl', 8368404), (8368396, 'b', 8368428), (8368424, 'b', 8368428), (8368496, 'bpl', 8368584), (8368576, 'b', 8368608), (8368604, 'b', 8368608), (8368700, 'b', 8369116), (8368760, 'bpl', 8368824), (8368820, 'b', 8368848), (8368844, 'b', 8368848), (8368916, 'bpl', 8369000), (8368996, 'b', 8369024), (8369020, 'b', 8369024), (8369116, 'b', 8369560), (8369172, 'bpl', 8369240), (8369232, 'b', 8369264), (8369260, 'b', 8369264), (8369332, 'bpl', 8369444), (8369412, 'b', 8369468), (8369464, 'b', 8369468), (8369848, 'b', 8371292), (8369940, 'bpl', 8370816), (8369976, 'beq', 8370400), (8370032, 'bpl', 8370096), (8370092, 'b', 8370120), (8370116, 'b', 8370120), (8370188, 'bpl', 8370276), (8370268, 'b', 8370300), (8370296, 'b', 8370300), (8370392, 'b', 8370812), (8370452, 'bpl', 8370520), (8370512, 'b', 8370544), (8370540, 'b', 8370544), (8370612, 'bpl', 8370696), (8370692, 'b', 8370720), (8370716, 'b', 8370720), (8370812, 'b', 8371240), (8370868, 'bpl', 8370932), (8370928, 'b', 8370956), (8370952, 'b', 8370956), (8371024, 'bpl', 8371124), (8371104, 'b', 8371148), (8371144, 'b', 8371148), (8371328, 'bne', 8373544), (8371456, 'bpl', 8372300), (8371492, 'beq', 8371904), (8371548, 'bpl', 8371624), (8371608, 'b', 8371648), (8371644, 'b', 8371648), (8371716, 'bpl', 8371808), (8371796, 'b', 8371832), (8371828, 'b', 8371832), (8371900, 'b', 8372296), (8371956, 'bpl', 8372024), (8372016, 'b', 8372048), (8372044, 'b', 8372048), (8372116, 'bpl', 8372208), (8372196, 'b', 8372232), (8372228, 'b', 8372232), (8372296, 'b', 8372692), (8372352, 'bpl', 8372416), (8372412, 'b', 8372440), (8372436, 'b', 8372440), (8372508, 'bpl', 8372604), (8372588, 'b', 8372628), (8372624, 'b', 8372628), (8373264, 'beq', 8373360), (8373520, 'b', 8374920), (8373624, 'bpl', 8374384), (8373660, 'beq', 8374032), (8373716, 'bpl', 8373788), (8373772, 'b', 8373808), (8373804, 'b', 8373808), (8373868, 'bpl', 8373948), (8373944, 'b', 8373968), (8373964, 'b', 8373968), (8374028, 'b', 8374380), (8374084, 'bpl', 8374144), (8374140, 'b', 8374164), (8374160, 'b', 8374164), (8374224, 'bpl', 8374304), (8374300, 'b', 8374324), (8374320, 'b', 8374324), (8374380, 'b', 8374748), (8374436, 'bpl', 8374496), (8374492, 'b', 8374516), (8374512, 'b', 8374516), (8374576, 'bpl', 8374672), (8374652, 'b', 8374692), (8374688, 'b', 8374692), (8374920, 'b', 8381700), (8375076, 'bne', 8375896), (8375264, 'bpl', 8375348), (8375320, 'b', 8375368), (8375364, 'b', 8375368), (8375428, 'bpl', 8375512), (8375504, 'b', 8375532), (8375528, 'b', 8375532), (8375892, 'b', 8376388), (8376036, 'bpl', 8376096), (8376092, 'b', 8376116), (8376112, 'b', 8376116), (8376176, 'bpl', 8376256), (8376252, 'b', 8376276), (8376272, 'b', 8376276), (8376424, 'bne', 8377648), (8376612, 'bpl', 8376688), (8376668, 'b', 8376708), (8376704, 'b', 8376708), (8376768, 'bpl', 8376912), (8376844, 'b', 8376932), (8376928, 'b', 8376932), (8377640, 'b', 8378448), (8378016, 'bpl', 8378076), (8378072, 'b', 8378096), (8378092, 'b', 8378096), (8378156, 'bpl', 8378240), (8378232, 'b', 8378260), (8378256, 'b', 8378260), (8378484, 'bne', 8378532), (8378524, 'bne', 8378532), (8378528, 'b', 8378532), (8378624, 'beq', 8379728), (8378664, 'beq', 8379720), (8378868, 'bpl', 8379292), (8378924, 'bpl', 8379016), (8378980, 'b', 8379036), (8379032, 'b', 8379036), (8379096, 'bpl', 8379184), (8379172, 'b', 8379204), (8379200, 'b', 8379204), (8379288, 'b', 8379668), (8379344, 'bpl', 8379404), (8379400, 'b', 8379424), (8379420, 'b', 8379424), (8379484, 'bpl', 8379564), (8379560, 'b', 8379584), (8379580, 'b', 8379584), (8379720, 'b', 8381696), (8379844, 'bpl', 8379912), (8379900, 'b', 8379932), (8379928, 'b', 8379932), (8379992, 'bpl', 8380080), (8380068, 'b', 8380100), (8380096, 'b', 8380100), (8380848, 'bpl', 8381252), (8380904, 'bpl', 8380976), (8380960, 'b', 8380996), (8380992, 'b', 8380996), (8381056, 'bpl', 8381140), (8381132, 'b', 8381160), (8381156, 'b', 8381160), (8381244, 'b', 8381644), (8381304, 'bpl', 8381380), (8381360, 'b', 8381400), (8381396, 'b', 8381400), (8381460, 'bpl', 8381540), (8381536, 'b', 8381560), (8381556, 'b', 8381560), (8381696, 'b', 8381700)],
        semantics=('LoadWorldUI -[optionsButton:] @0x007f94ec (5164 words, 220 branches, 110 calls; [census] grade): the options/settings overlay builder+refresher - the heaviest body of this batch. Prologue push {r4,r5,r6,r7,r8,sl,fp,lr}; add fp,sp,#0x18; sub sp,#0x2a8 then sub sp,#0x800 (~2.7 KB frame); the PIC base 0x0105faf4 is re-derived from pool cell 0x007fa4b0 (and again at 0x007fe590 for the tail). Re-entry guard: if self->backButton@48 (.got 0x0105db20) != nil -> bne 0x007fa04c, skipping the whole construction chain 0x007f9538..0x007fa048, so an already-built menu is only refreshed. Control flow: 220 branches = 135 unconditional \'b\', 66 \'bpl\', 9 \'bne\', 10 \'beq\'; every target is forward, zero backward branches (no loop); 373 block boundaries / 372 basic blocks (median 28 words), the longest straight-line stretches being 792 words @0x007f97a8, 748 @0x007fdec4, 708 @0x007fd264, 640 @0x007f9dcc / 0x007fa61c / 0x007fad50. Call census (110): 60 indirect sends (blx r3 x27, blx lr x21, blx ip x5, blx r2 x4, blx r4 x2, blx r6 x1), 19 direct \'bl loc.imp.objc_msgSend\', 29 calls to the 19-instruction float4 packer at 0x007ed878 and 2 calls to its twin 0x007ed8c4 (used to pack the {1,1,1,1} colours). Send table by receiver (79 sends): [MJButton alloc] x7 + [MJButton initWithFrame:cache:windowInfo:title:] x7; [MJTextView alloc] x2 + [MJTextView initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:] x2; [BitmapFont standardFont] x2 (classref 0x00e8a784, dereferenced); [self->cache@12 textureNamed:] x13; backButton@48 x3 (setBackgroundTexture:, setBackgroundSelectedTexture:, setTarget:self action:backButton:); deleteWorldButton@52 x7; onlineOwnerPortalButton@140 x4 (incl. one release of the previous instance); onlineShareButton@136 x3; onlinePicButton@132 x7 (incl. setGlyphTexture: x2, setTitleAlignment:1); onlinePicTextView@128 x1; worldNameTextView@80 x1; worldNameButton@84 x5 (incl. setGlyphTexture:, setTitleAlignment:1, setTitle:, setFrame:); migrateToCustomButton@92 x4; self->gameSave@36 x9 (objectForKey: x5, boolValue x3, uppercaseString x1). Construction - every element gets a centred rect packed by 0x007ed878 as {x = -w/2, y, w, h}, the constant fields coming from movw/movt pairs: 226.0 (0x43620000) x12, -113.0 (= -226/2, 0xc2e20000) x14, 40.0 (0x42200000) x19, 256.0 (0x43800000) x6, -4.0 x4, -117.0 x2, 48.0 x2, 16.0 x8, and the 178.0 / -65.0 pair used for the narrow variant of the share button; y comes from the windowInfo cursor math (float pool constants 415.0 x68, 48.0 x37, 160.0 x29, 0.0 x29, -44.0 x27, 144.0, -48.0, plus vmov.f32 #1 and the 66 FP compares). Buttons and their titles/targets: backButton@48 \'<- BACK\' (CFString 0x00f91a38) with InventoryButtonBackground.png / ...Selected.png (0x00f91848/0x00f91858); deleteWorldButton@52 with the Red pair InventoryButtonBackgroundRed.png / ...SelectedRed.png (0x00f91a58/0x00f91a68) and target deleteWorldButton:, its title set later by the state switch (\'DELETE WORLD\' 0x00f91a48 / \'FORGET WORLD\' 0x00f91a78); onlineOwnerPortalButton@140 \'OWNER PORTAL...\' (0x00f91a98) created after the old object is released (CALL34 at 0x007fa90c) and re-allocated; onlineShareButton@136 \'INVITE TO WORLD...\' (0x00f91aa8); onlinePicButton@132 (small 40-high rects, setGlyphTexture: + setTitleAlignment:1); worldNameButton@84 with the \'textEntry.png\' (0x00f91ae8) glyph texture, setTitleAlignment:1 and title = [[self->gameSave objectForKey:@"worldName"] uppercaseString] (CALL89/90/91); migrateToCustomButton@92 with the Red texture pair, target migrateToCustomButton:, created after [[self->gameSave objectForKey:@"customRulesDict"] (0x00f91938)] is consulted and after an autorelease of a previous instance (CALL95). Text views (MJTextView, both with [BitmapFont standardFont], horizontalAlignment 2 and colour {1,1,1,1}): \'PIC:\' (0x00f91ab8) stored into onlinePicTextView@128 and \'WORLD NAME:\' (0x00f91ac8) into worldNameTextView@80. State switch (on both entry paths): [[self->gameSave@36 objectForKey:@"remoteGame" (0x00f918f8)] boolValue] - true -> self->state@40 = 2 (movw sl,2 at 0x007fa114, stored 0x007fa134) and [deleteWorldButton setTitle:@"FORGET WORLD"]; false (beq 0x007fca90) -> self->state@40 = 1 (movw r5,1 at 0x007fcac0, stored 0x007fcad8) with [deleteWorldButton setTitle:@"DELETE WORLD"]; [[gameSave objectForKey:@"cloudGame" (0x00f91a28)] boolValue] and [[gameSave objectForKey:@"isOwner" (0x00f91a88)] boolValue] gate the online-portal/share blocks. Tail: the last blocks recompute the same cursor geometry, pack rects into fp-0x118 / fp-0x138 and issue setFrame: on deleteWorldButton@52 - the function\'s final send CALL109 at 0x007fe4fc, then sub sp,fp,#0x18 / pop {r4,r5,r6,r7,r8,sl,fp,pc}. Verified setFrame: sites: CALL54 onlinePicTextView@128 (0x007fbc58), CALL70 onlinePicButton@132 (0x007fca4c), CALL79 worldNameTextView@80 (0x007fd040), CALL93 worldNameButton@84 (0x007fd84c), CALL98 (0x007fdd44) and CALL109 (0x007fe4fc) on deleteWorldButton@52. No delegate sends and no [super ...] anywhere in the body - it is pure construction; the actions it wires (backButton:, deleteWorldButton:, migrateToCustomButton:, onlineOwnerPortalButton:, onlinePicButton:, onlineShareButton:, worldNameButton:) are sibling bodies of this batch.'),
    ),
    dict(
        name='lwu_28',
        method='LoadWorldUI -[playButton:]',
        types='v12@0:4@8',
        start=8360408,
        end=8361196,
        disasm='disasm_worldtileloader_lwu_28.txt',
        base_add=8360424,
        base_literal=8361192,
        boundary='ARM.exidx end 0x007f94ec (listing bound); next ObjC IMP 0x007f94ec LoadWorldUI -[optionsButton:]',
        selectors={
                 0x7f94bc: (15211252, 'boolValue'),
                 0x7f94c4: (15211224, 'objectForKey:'),
                 0x7f94cc: (15211320, 'loadWorldPlayButtonTapped'),
                 0x7f94d4: (15211316, 'connectToWorldWithID:userName:delegate:'),
                 0x7f94e4: (15211312, 'startAttemptingToConnectToWorld'),
        },
        imports={
                 0x7f94b8: (17151904, 'objc_msgSend'),
                 0x7f94c0: (16324856, '__CFConstantStringClassReference'),
                 0x7f94c8: (16325160, '__CFConstantStringClassReference'),
                 0x7f94d8: (16324888, '__CFConstantStringClassReference'),
                 0x7f94dc: (16324808, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7f94b4: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
                 0x7f94d0: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
                 0x7f94e0: (17160896, 'OBJC_IVAR_$_LoadWorldUI.cloudInterface', 16),
        },
        classes={},
        instructions=[(8360408, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8361192, 'addeq r6, r6, r4, lsl 18')],
        calls=[(8360572, 'blx ip'), (8360588, 'blx r2'), (8360696, 'blx ip'), (8360712, 'blx r2'), (8360880, 'blx r8'), (8360948, 'blx lr'), (8361000, 'blx ip'), (8361056, 'blx lr'), (8361124, 'blx r2')],
        branches=[(8360476, 'beq', 8361132), (8360600, 'beq', 8361064), (8360724, 'beq', 8361064), (8361060, 'b', 8361128), (8361128, 'b', 8361132)],
        semantics=('LoadWorldUI -[playButton:] @0x007f91d8 (197 words, 5 branches, 9 calls): world-play dispatcher for the selected world card. Guard: if self->gameSave@36 == nil it returns at once (cmp against a movw-zero). Then two flags are read from the save dictionary as [[gameSave objectForKey:K] boolValue]: K=@"remoteGame" (const string 0x00f918f8, cell 0x007f94c0) and K=@"cloudGame" (0x00f91a28, cell 0x007f94c8). If remoteGame is NO, or (when it is YES) cloudGame is NO, it falls to the shared tail block 0x007f9468: [self->delegate@4 loadWorldPlayButtonTapped] (SEL cell 0x007f94cc) and returns. Only when BOTH flags are YES does the cloud path run: first [self->delegate startAttemptingToConnectToWorld] (SEL 0x007f94e4); then worldID=[gameSave objectForKey:@"saveID"] (const 0x00f918c8) and userName=[gameSave objectForKey:@"userName"] (const 0x00f91918, cell 0x007f94d8); finally [self->cloudInterface@16 connectToWorldWithID:worldID userName:userName delegate:self] (SEL 0x007f94d4, 5th arg self via str ip,[sp], objc_msgSend ptr fetched once at 0x007f91f0 and re-cached in [fp,-0x2c]/[fp,-0x30]/[fp,-0x3c] etc.). All sends are blx through register-cached objc_msgSend. Base T=pc+0x866904=0x0105faf4.'),
    ),
    dict(
        name='lwu_29',
        method='LoadWorldUI -[renderFrame:projectionMatrix:]',
        types='v76@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12',
        start=8348712,
        end=8360408,
        disasm='disasm_worldtileloader_lwu_29.txt',
        base_add=8348740,
        base_literal=8351416,
        boundary='ARM.exidx end 0x007f91d8 (listing bound); next ObjC IMP 0x007f91d8 LoadWorldUI -[playButton:]',
        selectors={
                 0x7f6ec4: (15211204, 'count'),
                 0x7f6ed0: (15211208, 'objectAtIndex:'),
                 0x7f6ed8: (15211300, 'renderFrame:projectionMatrix:center:'),
                 0x7f6edc: (15211308, 'attemptingToConnectToWorld'),
                 0x7f787c: (15211304, 'renderFrame:projectionMatrix:'),
                 0x7f91b0: (15211304, 'renderFrame:projectionMatrix:'),
        },
        imports={
                 0x7f6ec0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7f6ebc: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x7f6ec8: (17161008, 'OBJC_IVAR_$_LoadWorldUI.blockheadPreviews', 32),
                 0x7f6ed4: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7f6ee0: (17160904, 'OBJC_IVAR_$_LoadWorldUI.delegate', 4),
                 0x7f6ee4: (17160908, 'OBJC_IVAR_$_LoadWorldUI.blockheadNamesTextView', 28),
                 0x7f7880: (17160912, 'OBJC_IVAR_$_LoadWorldUI.playButton', 20),
                 0x7f7888: (17160920, 'OBJC_IVAR_$_LoadWorldUI.disabledTextView', 56),
                 0x7f788c: (17160916, 'OBJC_IVAR_$_LoadWorldUI.optionsButton', 24),
                 0x7f7890: (17160992, 'OBJC_IVAR_$_LoadWorldUI.backButton', 48),
                 0x7f7898: (17160988, 'OBJC_IVAR_$_LoadWorldUI.deleteWorldButton', 52),
                 0x7f81e0: (17160984, 'OBJC_IVAR_$_LoadWorldUI.worldNameTextView', 80),
                 0x7f81e4: (17160980, 'OBJC_IVAR_$_LoadWorldUI.worldNameButton', 84),
                 0x7f852c: (17160976, 'OBJC_IVAR_$_LoadWorldUI.hostMultiButton', 88),
                 0x7f8530: (17160972, 'OBJC_IVAR_$_LoadWorldUI.migrateToCustomButton', 92),
                 0x7f8538: (17161012, 'OBJC_IVAR_$_LoadWorldUI.onlinePicTextView', 128),
                 0x7f853c: (17161020, 'OBJC_IVAR_$_LoadWorldUI.onlinePicButton', 132),
                 0x7f8540: (17161024, 'OBJC_IVAR_$_LoadWorldUI.onlineShareButton', 136),
                 0x7f8544: (17161028, 'OBJC_IVAR_$_LoadWorldUI.onlineOwnerPortalButton', 140),
                 0x7f91a4: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x7f91a8: (17160992, 'OBJC_IVAR_$_LoadWorldUI.backButton', 48),
                 0x7f91b4: (17160964, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameTitleTextView', 100),
                 0x7f91b8: (17160960, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameButton', 104),
                 0x7f91bc: (17160956, 'OBJC_IVAR_$_LoadWorldUI.hostPicTextView', 108),
                 0x7f91c0: (17160952, 'OBJC_IVAR_$_LoadWorldUI.hostPicButton', 112),
                 0x7f91c4: (17160948, 'OBJC_IVAR_$_LoadWorldUI.hostPvpTitleTextView', 116),
                 0x7f91c8: (17160944, 'OBJC_IVAR_$_LoadWorldUI.hostPvpButton', 120),
                 0x7f91cc: (17160940, 'OBJC_IVAR_$_LoadWorldUI.hostNowButton', 124),
                 0x7f91d4: (17160968, 'OBJC_IVAR_$_LoadWorldUI.hostMultiLANButton', 96),
        },
        classes={},
        instructions=[(8348712, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8360404, 'invalid')],
        calls=[(8349076, 'blx r2'), (8349168, 'blx r2'), (8349244, 'bl loc.imp.objc_msgSend'), (8349444, 'bl method.constructor.Vector2.Vector2_float__float_'), (8349712, 'bl loc.imp.objc_msgSend'), (8350180, 'bl loc.imp.objc_msgSend'), (8350216, 'blx r3'), (8350644, 'bl loc.imp.objc_msgSend'), (8351028, 'bl loc.imp.objc_msgSend'), (8351408, 'bl loc.imp.objc_msgSend'), (8351528, 'blx r2'), (8351992, 'bl loc.imp.objc_msgSend'), (8352376, 'bl loc.imp.objc_msgSend'), (8352760, 'bl loc.imp.objc_msgSend'), (8353144, 'bl loc.imp.objc_msgSend'), (8353528, 'bl loc.imp.objc_msgSend'), (8353908, 'bl loc.imp.objc_msgSend'), (8354396, 'bl loc.imp.objc_msgSend'), (8354780, 'bl loc.imp.objc_msgSend'), (8355164, 'bl loc.imp.objc_msgSend'), (8355548, 'bl loc.imp.objc_msgSend'), (8355932, 'bl loc.imp.objc_msgSend'), (8356312, 'bl loc.imp.objc_msgSend'), (8356776, 'bl loc.imp.objc_msgSend'), (8357156, 'bl loc.imp.objc_msgSend'), (8357640, 'bl loc.imp.objc_msgSend'), (8358024, 'bl loc.imp.objc_msgSend'), (8358408, 'bl loc.imp.objc_msgSend'), (8358792, 'bl loc.imp.objc_msgSend'), (8359176, 'bl loc.imp.objc_msgSend'), (8359560, 'bl loc.imp.objc_msgSend'), (8359944, 'bl loc.imp.objc_msgSend'), (8360324, 'bl loc.imp.objc_msgSend')],
        branches=[(8349012, 'bne', 8351468), (8349084, 'bls', 8349736), (8349180, 'bhs', 8349732), (8349728, 'b', 8349100), (8349732, 'b', 8349736), (8350228, 'bne', 8351412), (8351412, 'b', 8360348), (8351540, 'bne', 8360344), (8351576, 'bne', 8353948), (8353912, 'b', 8360340), (8353980, 'bne', 8356328), (8356316, 'b', 8360336), (8356360, 'bne', 8357192), (8357160, 'b', 8360332), (8357224, 'bne', 8360328), (8360328, 'b', 8360332), (8360332, 'b', 8360336), (8360336, 'b', 8360340), (8360340, 'b', 8360344), (8360344, 'b', 8360348)],
        semantics=('LoadWorldUI -[renderFrame:projectionMatrix:] @0x007f6428 (2924 words, 20 branches, 33 calls, census). Whole-screen render pass; types v76@0:4f8(_GLKMatrix4=[16 floats])12 = float layerDepth in r2 plus a 64-byte GLKMatrix4 passed on the caller stack. PROLOGUE: push {r4-r8,sl,fp,lr}; fp=sp+0x18; sub sp,#0xc60; bic sp,#0xf; sl=sp+0xc00; the 16 matrix words are read from [fp,8..0x44] and re-materialised into a scratch copy at [sp,0xc20..0xc5c]; the depth float is vmov\'d out of s0 and stored at [sp,0x4e0]; self is kept at [sp,0xc1c] and the PIC base register (ip) is spilled to [sp,0x4fc]. State read: OBJC_IVAR_$_LoadWorldUI.state@40 (offset cell 0x105dabc, loaded through pool cell 0x007f6ebc=0xffffdfc8), `cmp #0; bne 0x7f6eec` - the state==0 screen is the fall-through path. STATE 0 (world list, 0x7f6558..0x7f6eb0): loop over [self->blockheadPreviews@32 count] with index at [sp,0xc10]: `[self->blockheadPreviews count]` (blx r2, sel count) -> if count<=0 (bls 0x7f6828) skip; else per iteration `[self->blockheadPreviews objectAtIndex:i]` (bl loc.imp.objc_msgSend, selref objectAtIndex: 0xe81ac8) into [sp,0xc0c], the matrix is copied per-iteration into an outgoing stack block ([sp,0xbc0..0xbfc]), two words of self->windowInfo@8 (fields +8/+0xc) are passed to the C++ constructor bl method.constructor.Vector2.Vector2_float__float_ (0x7f6704, the only non-ObjC callee) to build the `center` argument, and the preview is drawn with `[preview renderFrame:<float r2> projectionMatrix:<stack struct> center:<Vector2>]` (blx r2, selref renderFrame:projectionMatrix:center: 0xe81b24); loop increment i++ at 0x7f6814-0x7f681c and back-edge `b 0x7f65ac` (0x7f6820), exit via `bhs 0x7f6824`. After the loop: `[self->blockheadNamesTextView@28 renderFrame:proj]` (0x7f69e4), then `if ([self->delegate@4 attemptingToConnectToWorld]) return;` (objc_msgSend at 0x7f6a08, sxtb/cmp, bne 0x7f6eb4 -> epilogue), then playButton@20 (0x7f6bb4), disabledTextView@56 (0x7f6d34) and optionsButton@24 (0x7f6eb0), then `b 0x7f919c`. STATE 1 (0x7f6eec..0x7f7878): delegate attemptingToConnectToWorld check first (send 0x7f6f28, bne 0x7f9198 -> epilogue), then state!=1 -> 0x7f789c; renders backButton@48, deleteWorldButton@52, worldNameTextView@80, worldNameButton@84, hostMultiButton@88, migrateToCustomButton@92; `b 0x7f9194`. STATE 2 (0x7f789c): state!=2 -> 0x7f81e8; backButton@48, deleteWorldButton@52, onlinePicTextView@128, onlinePicButton@132, onlineShareButton@136, onlineOwnerPortalButton@140; `b 0x7f9190`. STATE 3 (0x7f81e8): state!=3 -> 0x7f8548; backButton@48, hostMultiLANButton@96; `b 0x7f918c`. STATE 4 (0x7f8548, 784 words): state!=4 -> 0x7f9188; backButton@48, hostNickNameTitleTextView@100, hostNickNameButton@104, hostPicTextView@108, hostPicButton@112, hostPvpTitleTextView@116, hostPvpButton@120, hostNowButton@124. TAIL: the five chained `b` at 0x7f9188/0x7f918c/0x7f9190/0x7f9194/0x7f9198 converge on `pop {r4,r5,r6,r7,r8,sl,fp,pc}` at 0x7f919c-0x7f91a0. CLASSES/CALLS: 33 calls = 28 direct `bl loc.imp.objc_msgSend` (26 renderFrame:projectionMatrix: draws - 4 state-0 / 6 state-1 / 6 state-2 / 2 state-3 / 8 state-4 - plus the two delegate attemptingToConnectToWorld checks), 3 `blx r2` inside the preview loop (count, objectAtIndex:, renderFrame:...:center:) and 1 `blx r3` (state-0 delegate check), plus the single C++ Vector2 constructor call; there is NO objc_msgSendSuper2 (no super render) and no string literals, and the receiver of every draw is an ivar of LoadWorldUI fetched through its OBJC_IVAR_$_LoadWorldUI.<name> offset cell, so this body is purely the screen\'s own child renderer driven by the same state machine as -[startTouch:]. Verified independently by a cell-reference census: 43 distinct literal-pool cells / 61 pool loads, all resolving through PIC base 0x105faf4 to LoadWorldUI ivar offset variables, the two shared selector slots (renderFrame:projectionMatrix: @0xe81b28, renderFrame:projectionMatrix:center: @0xe81b24, count @0xe81ac4, objectAtIndex: @0xe81ac8, attemptingToConnectToWorld @0xe81b2c) and the objc_msgSend GOT pointer @0x105b7a0 (cell 0x007f6ec0=0xffffbcac).'),
    ),
    dict(
        name='lwu_30',
        method='LoadWorldUI -[startTouch:]',
        types='c16@0:4{CGPoint=ff}8',
        start=8403956,
        end=8406576,
        disasm='disasm_worldtileloader_lwu_30.txt',
        base_add=8403972,
        base_literal=8406572,
        boundary='ARM.exidx end 0x00804630 (listing bound); next ObjC IMP 0x00804630 LoadWorldUI -[moveTouch:]',
        selectors={
                 0x8045a8: (15211412, 'startTouch:'),
        },
        imports={},
        ivars={
                 0x80459c: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x8045a0: (17160992, 'OBJC_IVAR_$_LoadWorldUI.backButton', 48),
                 0x8045ac: (17160960, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameButton', 104),
                 0x8045b4: (17160952, 'OBJC_IVAR_$_LoadWorldUI.hostPicButton', 112),
                 0x8045bc: (17160944, 'OBJC_IVAR_$_LoadWorldUI.hostPvpButton', 120),
                 0x8045c4: (17160940, 'OBJC_IVAR_$_LoadWorldUI.hostNowButton', 124),
                 0x8045d0: (17160968, 'OBJC_IVAR_$_LoadWorldUI.hostMultiLANButton', 96),
                 0x8045dc: (17160988, 'OBJC_IVAR_$_LoadWorldUI.deleteWorldButton', 52),
                 0x8045e4: (17161020, 'OBJC_IVAR_$_LoadWorldUI.onlinePicButton', 132),
                 0x8045ec: (17161024, 'OBJC_IVAR_$_LoadWorldUI.onlineShareButton', 136),
                 0x8045f4: (17161028, 'OBJC_IVAR_$_LoadWorldUI.onlineOwnerPortalButton', 140),
                 0x804604: (17160980, 'OBJC_IVAR_$_LoadWorldUI.worldNameButton', 84),
                 0x80460c: (17160976, 'OBJC_IVAR_$_LoadWorldUI.hostMultiButton', 88),
                 0x804614: (17160972, 'OBJC_IVAR_$_LoadWorldUI.migrateToCustomButton', 92),
                 0x80461c: (17160912, 'OBJC_IVAR_$_LoadWorldUI.playButton', 20),
                 0x804624: (17160916, 'OBJC_IVAR_$_LoadWorldUI.optionsButton', 24),
        },
        classes={},
        instructions=[(8403956, 'push {r4, sl, fp, lr}'), (8406572, 'addeq fp, r5, r8, ror 29')],
        calls=[(8404116, 'bl loc.imp.objc_msgSend'), (8404232, 'bl loc.imp.objc_msgSend'), (8404388, 'bl loc.imp.objc_msgSend'), (8404504, 'bl loc.imp.objc_msgSend'), (8404620, 'bl loc.imp.objc_msgSend'), (8404736, 'bl loc.imp.objc_msgSend'), (8404852, 'bl loc.imp.objc_msgSend'), (8405008, 'bl loc.imp.objc_msgSend'), (8405124, 'bl loc.imp.objc_msgSend'), (8405240, 'bl loc.imp.objc_msgSend'), (8405356, 'bl loc.imp.objc_msgSend'), (8405472, 'bl loc.imp.objc_msgSend'), (8405628, 'bl loc.imp.objc_msgSend'), (8405744, 'bl loc.imp.objc_msgSend'), (8405900, 'bl loc.imp.objc_msgSend'), (8406016, 'bl loc.imp.objc_msgSend'), (8406132, 'bl loc.imp.objc_msgSend'), (8406248, 'bl loc.imp.objc_msgSend'), (8406364, 'bl loc.imp.objc_msgSend')],
        branches=[(8404032, 'bne', 8404272), (8404052, 'bne', 8404140), (8404168, 'bne', 8404256), (8404268, 'b', 8406416), (8404304, 'bne', 8404892), (8404324, 'bne', 8404412), (8404440, 'bne', 8404528), (8404556, 'bne', 8404644), (8404672, 'bne', 8404760), (8404788, 'bne', 8404876), (8404888, 'b', 8406412), (8404924, 'bne', 8405512), (8404944, 'bne', 8405032), (8405060, 'bne', 8405148), (8405176, 'bne', 8405264), (8405292, 'bne', 8405380), (8405408, 'bne', 8405496), (8405508, 'b', 8406408), (8405544, 'bne', 8405784), (8405564, 'bne', 8405652), (8405680, 'bne', 8405768), (8405780, 'b', 8406404), (8405816, 'bne', 8406400), (8405836, 'bne', 8405924), (8405952, 'bne', 8406040), (8406068, 'bne', 8406156), (8406184, 'bne', 8406272), (8406300, 'bne', 8406388), (8406400, 'b', 8406404), (8406404, 'b', 8406408), (8406408, 'b', 8406412), (8406412, 'b', 8406416)],
        semantics=('LoadWorldUI -[startTouch:] @0x00803bf4 (655 words, 32 branches, 19 calls, census-lite): CGPoint touch dispatcher for the load-world screen. Entry spills the two raw words of the CGPoint argument (r2->[fp,-0x10], r3->[fp,-0xc]), self->_cmd to [fp,-0x14]/[fp,-0x18] and initialises the handled flag [fp,-0x19]=0; frame sub sp,#0x100; PIC base anchor cell 0x0080462c=0x85bee8. It reads state@40 (ivar offset cell 0x105dabc, OBJC_IVAR_$_LoadWorldUI.state) and selects a button-set by state: state==0 -> [self->playButton@20 startTouch:point], then if that returned 0 [self->optionsButton@24 startTouch:point]; state==1 -> backButton@48, deleteWorldButton@52, worldNameButton@84, hostMultiButton@88, migrateToCustomButton@92; state==2 -> backButton@48, deleteWorldButton@52, onlinePicButton@132, onlineShareButton@136, onlineOwnerPortalButton@140; state==3 -> backButton@48, hostMultiLANButton@96; state==4 -> backButton@48, hostNickNameButton@104, hostPicButton@112, hostPvpButton@120, hostNowButton@124; any other state jumps straight to the shared epilogue. All 19 sends go through objc_msgSend (bl loc.imp.objc_msgSend, no super2, no blx) with the single selector startTouch: (selref slot 0xe81b94) and the CGPoint re-loaded from [fp,-0x10]/[fp,-0xc] into r2/r3; each receiver object is fetched by self+OBJC_IVAR_$_LoadWorldUI.<name>. Every reply is folded back through sxtb/cmp/movw/movne -> the handled byte [fp,-0x19], so a button is tried only while handled==NO. Tail: conditional chain 0x803d2c b 0x804590 / 0x803f98 b 0x80458c / 0x804204 b 0x804588 / 0x804314 b 0x804584 / 0x804580 b 0x804584 and the 5 chained `b` at 0x804580-0x80458c all converge on `ldrsb r0,[fp,-0x19]; sub sp,fp,8; pop {r4,sl,fp,pc}` (returns char, matching types c16@0:4{CGPoint=ff}8). The CGPoint is passed by value in r2/r3 (no VFP moves anywhere in the body).'),
    ),
    dict(
        name='lwu_31',
        method='LoadWorldUI -[state]',
        types='i8@0:4',
        start=8423404,
        end=8423464,
        disasm='disasm_worldtileloader_lwu_31.txt',
        base_add=8423428,
        base_literal=8423460,
        boundary='ARM.exidx end 0x00808828 (listing bound); next ObjC IMP 0x00809210 LimeTree -[objectType]',
        selectors={},
        imports={},
        ivars={
                 0x808820: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
        },
        classes={},
        instructions=[(8423404, 'sub sp, sp, 8'), (8423460, 'addeq r7, r5, r8, ror 5')],
        calls=[],
        branches=[],
        semantics=('LoadWorldUI -[state] @0x008087ec (15 words, 0 branches, 0 calls, read): Apportable offset-cell getter for the int ivar state@40 (GNU cross-check names it OBJC_IVAR_$_LoadWorldUI.state; offset variable at 0x105dabc in __DATA,__objc_ivar, value 0x28). Sequence: ldr r1,[0x00808820]=0xffffdfc8; ldr r2,[0x00808824]=0x008572e8; add r2,pc,r2 (PIC base 0x105faf4); ldr r1,[r1,r2] (ivar-offset cell); ldr r1,[r1] (offset 40); ldr r0,[r0,r1]; \'dmb ish\' (word 0xf57ff05b, printed identically by GNU objdump); add sp,sp,8; bx lr. No retain/release, no branches. Last LoadWorldUI IMP in address order - the next ObjC IMP in the binary is 0x00809210 LimeTree -[objectType], so the whole span up to that address belongs to other classes\' code (roster boundary note).'),
    ),
    dict(
        name='lwu_32',
        method='LoadWorldUI -[textField:shouldChangeCharactersInRange:replacementString:]',
        types='c24@0:4@8{_NSRange=II}12@20',
        start=8409792,
        end=8410452,
        disasm='disasm_worldtileloader_lwu_32.txt',
        base_add=8409808,
        base_literal=8410448,
        boundary='ARM.exidx end 0x00805554 (listing bound); next ObjC IMP 0x00805554 LoadWorldUI -[alertView:didDismissWithButtonIndex:]',
        selectors={
                 0x805528: (15211284, 'length'),
                 0x80552c: (15211424, 'text'),
                 0x805530: (15211432, 'rangeOfCharacterFromSet:'),
                 0x805534: (15211428, 'lowercaseLetterCharacterSet'),
                 0x805540: (15211440, 'setText:'),
                 0x805548: (15211348, 'uppercaseString'),
                 0x80554c: (15211436, 'stringByReplacingCharactersInRange:withString:'),
        },
        imports={
                 0x805524: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x805538: (15247280, 'OBJC_CLASS_$_NSCharacterSet'),
        },
        instructions=[(8409792, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8410448, 'addeq sl, r5, ip, lsl r8')],
        calls=[(8409892, 'blx r5'), (8409908, 'blx r2'), (8409940, 'blx r3'), (8410060, 'blx r3'), (8410116, 'bl loc.imp.objc_msgSend_stret'), (8410152, 'bl sym.imp.memset'), (8410244, 'bl loc.imp.objc_msgSend'), (8410292, 'bl loc.imp.objc_msgSend'), (8410336, 'bl loc.imp.objc_msgSend'), (8410368, 'blx r3')],
        branches=[(8409972, 'bls', 8409988), (8409984, 'b', 8410392), (8410096, 'beq', 8410124), (8410120, 'b', 8410156), (8410168, 'beq', 8410384), (8410380, 'b', 8410392)],
        semantics=('LoadWorldUI -[textField:shouldChangeCharactersInRange:replacementString:] @0x008052c0 (165 words, 6 branches, 10 calls): world-name text-field input filter (types c24@0:4@8{_NSRange=II}12@20: textField=r2, range={r3,[fp,8]}, replacementString=[fp,0xc]). Returns BOOL in [fp,-0x19]. (1) Length rule: newLen = [textField text].length + [replacementString length] - range.length (three sends: \'text\'/0x805528, \'length\'/0x805528, \'length\'); if newLen > 16 (cmp #0x10, only unsigned bls falls through) it returns NO immediately. (2) Lowercase rule: set = [NSCharacterSet lowercaseLetterCharacterSet] (class cell 0x00805538, SEL cells 0x00805534/0x00805530); rng = [replacementString rangeOfCharacterFromSet:set] via loc.imp.objc_msgSend_stret into [fp-0x48] (8 bytes; nil replacementString -> zeroed NSRange via memset fp-0x48,0,8). If rng.location == NSNotFound (0x7fffffff literal at 0x0080553c) it returns YES untouched. (3) Otherwise it rewrites the field itself: orig=[[textField text]]; up=[[replacementString uppercaseString]] (SEL cell 0x00805548); new = [orig stringByReplacingCharactersInRange:range withString:up] (SEL cell 0x0080554c, range words in r2/r3, \'up\' as 5th arg at [sp]); [textField setText:new] (SEL cell 0x00805540); returns NO. Net effect: world names are forced upper-case and capped at 16 characters. Base T=pc+0x85a81c=0x0105faf4 (re-anchored mid-body at 0x0080545c, same value).'),
    ),
    dict(
        name='lwu_33',
        method='LoadWorldUI -[textFieldShouldReturn:]',
        types='c12@0:4@8',
        start=8413340,
        end=8413472,
        disasm='disasm_worldtileloader_lwu_33.txt',
        base_add=8413356,
        base_literal=8413468,
        boundary='ARM.exidx end 0x00806120 (listing bound); next ObjC IMP 0x00806120 LoadWorldUI -[worldNameButton:]',
        selectors={
                 0x806114: (15211184, 'dismissWithClickedButtonIndex:animated:'),
        },
        imports={
                 0x806110: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x806118: (17161036, 'OBJC_IVAR_$_LoadWorldUI.textEntryAlertView', 64),
        },
        classes={},
        instructions=[(8413340, 'push {r4, r5, r6, sl, fp, lr}'), (8413468, 'addeq sb, r5, r0, asr 20')],
        calls=[(8413436, 'blx r4')],
        branches=[],
        semantics=('LoadWorldUI -[textFieldShouldReturn:] @0x0080609c (33 words, 0 branches, 1 call): world-name/rename text-field delegate. No state logic at all: it lights up one local word with the constant 1 (movw ip,#1 / lr,#1, also spilled to [sp]) and sends exactly one message - objc_msgSend via import cell 0x00806110 (blx r4) with receiver self->textEntryAlertView@64 (ivar cell 0x00806118), selector dismissWithClickedButtonIndex:animated:1 (SEL cell 0x00806114, T+0xffe21fbc), buttonIndex r2=1 and animated r3=sxtb(1)=YES. Return value is the same constant: r0=[sp] then sxtb r0,r0 -> returns YES. Frame: push {r4,r5,r6,sl,fp,lr}, fp=sp+0x10, 0x10 bytes locals.'),
    ),
    dict(
        name='lwu_34',
        method='LoadWorldUI -[windowInfoChanged:]',
        types='v12@0:4^{WindowInfo=ffffffff}8',
        start=8315136,
        end=8337104,
        disasm='disasm_worldtileloader_lwu_34.txt',
        base_add=8315156,
        base_literal=8319068,
        boundary='ARM.exidx end 0x007f36d0 (listing bound); next ObjC IMP 0x007f36d0 LoadWorldUI -[currentWorldChanged:]',
        selectors={
                 0x7ef068: (15211204, 'count'),
                 0x7ef070: (15211208, 'objectAtIndex:'),
                 0x7ef3d4: (15211212, 'setFrame:'),
                 0x7f13b8: (15211212, 'setFrame:'),
                 0x7f175c: (15211216, 'setString:'),
                 0x7f3460: (15211212, 'setFrame:'),
                 0x7f369c: (15211212, 'setFrame:'),
        },
        imports={
                 0x7ef064: (17151904, 'objc_msgSend'),
                 0x7f1758: (17151904, 'objc_msgSend'),
                 0x7f1760: (16324760, '__CFConstantStringClassReference'),
                 0x7f1764: (16324776, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7ef060: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7ef06c: (17161008, 'OBJC_IVAR_$_LoadWorldUI.blockheadPreviews', 32),
                 0x7ef3dc: (17160908, 'OBJC_IVAR_$_LoadWorldUI.blockheadNamesTextView', 28),
                 0x7ef638: (17160912, 'OBJC_IVAR_$_LoadWorldUI.playButton', 20),
                 0x7efa8c: (17160916, 'OBJC_IVAR_$_LoadWorldUI.optionsButton', 24),
                 0x7efda8: (17160992, 'OBJC_IVAR_$_LoadWorldUI.backButton', 48),
                 0x7efffc: (17160920, 'OBJC_IVAR_$_LoadWorldUI.disabledTextView', 56),
                 0x7f0450: (17160972, 'OBJC_IVAR_$_LoadWorldUI.migrateToCustomButton', 92),
                 0x7f0454: (17160988, 'OBJC_IVAR_$_LoadWorldUI.deleteWorldButton', 52),
                 0x7f0b94: (17160984, 'OBJC_IVAR_$_LoadWorldUI.worldNameTextView', 80),
                 0x7f0d54: (17160980, 'OBJC_IVAR_$_LoadWorldUI.worldNameButton', 84),
                 0x7f0fb8: (17160976, 'OBJC_IVAR_$_LoadWorldUI.hostMultiButton', 88),
                 0x7f0fbc: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7f13b4: (17160968, 'OBJC_IVAR_$_LoadWorldUI.hostMultiLANButton', 96),
                 0x7f1754: (17160964, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameTitleTextView', 100),
                 0x7f1c38: (17160960, 'OBJC_IVAR_$_LoadWorldUI.hostNickNameButton', 104),
                 0x7f1fd8: (17160956, 'OBJC_IVAR_$_LoadWorldUI.hostPicTextView', 108),
                 0x7f23fc: (17160952, 'OBJC_IVAR_$_LoadWorldUI.hostPicButton', 112),
                 0x7f272c: (17160892, 'OBJC_IVAR_$_LoadWorldUI.state', 40),
                 0x7f27dc: (17160948, 'OBJC_IVAR_$_LoadWorldUI.hostPvpTitleTextView', 116),
                 0x7f284c: (17160948, 'OBJC_IVAR_$_LoadWorldUI.hostPvpTitleTextView', 116),
                 0x7f2960: (17160944, 'OBJC_IVAR_$_LoadWorldUI.hostPvpButton', 120),
                 0x7f2e90: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7f3020: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7f311c: (17160940, 'OBJC_IVAR_$_LoadWorldUI.hostNowButton', 124),
                 0x7f3458: (17161012, 'OBJC_IVAR_$_LoadWorldUI.onlinePicTextView', 128),
                 0x7f34d4: (17161016, 'OBJC_IVAR_$_LoadWorldUI.onlinePlayerIsOwner', 144),
                 0x7f3694: (17160888, 'OBJC_IVAR_$_LoadWorldUI.windowInfo', 8),
                 0x7f36b0: (17161016, 'OBJC_IVAR_$_LoadWorldUI.onlinePlayerIsOwner', 144),
                 0x7f36b4: (17161020, 'OBJC_IVAR_$_LoadWorldUI.onlinePicButton', 132),
                 0x7f36bc: (17161024, 'OBJC_IVAR_$_LoadWorldUI.onlineShareButton', 136),
                 0x7f36c4: (17161028, 'OBJC_IVAR_$_LoadWorldUI.onlineOwnerPortalButton', 140),
        },
        classes={},
        instructions=[(8315136, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8337100, 'addeq ip, r6, ip, lsl 9')],
        calls=[(8315284, 'blx r2'), (8315388, 'blx r3'), (8315524, 'blx r3'), (8315620, 'bl 0x7ed878'), (8315820, 'blx r3'), (8315916, 'bl 0x7ed878'), (8316004, 'blx r3'), (8316100, 'bl 0x7ed878'), (8316156, 'bl loc.imp.objc_msgSend'), (8316600, 'bl 0x7ed878'), (8316652, 'bl loc.imp.objc_msgSend'), (8317164, 'bl 0x7ed878'), (8317328, 'bl 0x7ed878'), (8317576, 'bl 0x7ed878'), (8317684, 'bl loc.imp.objc_msgSend'), (8318200, 'bl 0x7ed878'), (8318272, 'bl 0x7ed878'), (8318516, 'bl 0x7ed878'), (8318624, 'bl loc.imp.objc_msgSend'), (8318948, 'bl 0x7ed878'), (8319200, 'bl 0x7ed878'), (8319308, 'bl loc.imp.objc_msgSend'), (8319760, 'bl 0x7ed878'), (8319832, 'bl 0x7ed878'), (8320076, 'bl 0x7ed878'), (8320176, 'bl loc.imp.objc_msgSend'), (8320672, 'bl 0x7ed878'), (8321080, 'bl 0x7ed878'), (8321548, 'bl 0x7ed878'), (8321976, 'bl 0x7ed878'), (8322100, 'bl loc.imp.objc_msgSend'), (8322644, 'bl 0x7ed878'), (8322696, 'bl loc.imp.objc_msgSend'), (8323300, 'bl 0x7ed878'), (8323348, 'bl loc.imp.objc_msgSend'), (8323808, 'bl 0x7ed878'), (8323860, 'bl loc.imp.objc_msgSend'), (8324344, 'bl 0x7ed878'), (8324396, 'bl loc.imp.objc_msgSend'), (8324740, 'bl 0x7ed878'), (8324968, 'bl 0x7ed878'), (8325136, 'bl loc.imp.objc_msgSend'), (8325236, 'blx r4'), (8325736, 'bl 0x7ed878'), (8326176, 'bl 0x7ed878'), (8326288, 'bl loc.imp.objc_msgSend'), (8326796, 'bl 0x7ed878'), (8327236, 'bl 0x7ed878'), (8327348, 'bl loc.imp.objc_msgSend'), (8327824, 'bl 0x7ed878'), (8328232, 'bl 0x7ed878'), (8328340, 'bl loc.imp.objc_msgSend'), (8328764, 'bl 0x7ed878'), (8329140, 'bl 0x7ed878'), (8329220, 'bl loc.imp.objc_msgSend'), (8329708, 'bl 0x7ed878'), (8329764, 'bl 0x7ed878'), (8329872, 'bl loc.imp.objc_msgSend'), (8330288, 'bl 0x7ed878'), (8330344, 'bl 0x7ed878'), (8330396, 'bl loc.imp.objc_msgSend'), (8330884, 'bl 0x7ed878'), (8330932, 'bl 0x7ed878'), (8331040, 'bl loc.imp.objc_msgSend'), (8331488, 'bl 0x7ed878'), (8331536, 'bl 0x7ed878'), (8331588, 'bl loc.imp.objc_msgSend'), (8332448, 'bl 0x7ed878'), (8332500, 'bl loc.imp.objc_msgSend'), (8332980, 'bl 0x7ed878'), (8333380, 'bl 0x7ed878'), (8333772, 'bl 0x7ed878'), (8333880, 'bl loc.imp.objc_msgSend'), (8334336, 'bl 0x7ed878'), (8334704, 'bl 0x7ed878'), (8335068, 'bl 0x7ed878'), (8335176, 'bl loc.imp.objc_msgSend'), (8335628, 'bl 0x7ed878'), (8336020, 'bl 0x7ed878'), (8336128, 'bl loc.imp.objc_msgSend'), (8336588, 'bl 0x7ed878'), (8336980, 'bl 0x7ed878'), (8337032, 'bl loc.imp.objc_msgSend')],
        branches=[(8315296, 'bhs', 8316180), (8315440, 'bpl', 8315628), (8315624, 'b', 8316108), (8315680, 'bmi', 8315740), (8315736, 'bpl', 8315924), (8315920, 'b', 8316104), (8316104, 'b', 8316108), (8316172, 'b', 8315216), (8316320, 'bpl', 8316336), (8316332, 'b', 8316484), (8316396, 'bmi', 8316464), (8316716, 'bmi', 8316776), (8316772, 'bpl', 8317336), (8316948, 'bpl', 8316964), (8316960, 'b', 8317112), (8317024, 'bmi', 8317092), (8317332, 'b', 8317580), (8317388, 'bpl', 8317448), (8317444, 'b', 8317468), (8317464, 'b', 8317468), (8317748, 'bmi', 8317808), (8317804, 'bpl', 8318284), (8317980, 'bpl', 8318000), (8317992, 'b', 8318148), (8318060, 'bmi', 8318128), (8318276, 'b', 8318520), (8318336, 'bpl', 8318408), (8318392, 'b', 8318428), (8318424, 'b', 8318428), (8318688, 'bpl', 8318956), (8318744, 'bpl', 8318804), (8318800, 'b', 8318824), (8318820, 'b', 8318824), (8318952, 'b', 8319204), (8319008, 'bpl', 8319092), (8319064, 'b', 8319112), (8319108, 'b', 8319112), (8319372, 'bmi', 8319432), (8319428, 'bpl', 8319844), (8319544, 'bpl', 8319560), (8319556, 'b', 8319708), (8319620, 'bmi', 8319688), (8319836, 'b', 8320080), (8319896, 'bpl', 8319972), (8319952, 'b', 8319992), (8319988, 'b', 8319992), (8320232, 'beq', 8321088), (8320288, 'bpl', 8320684), (8320344, 'bpl', 8320408), (8320400, 'b', 8320428), (8320424, 'b', 8320428), (8320488, 'bpl', 8320572), (8320564, 'b', 8320592), (8320588, 'b', 8320592), (8320676, 'b', 8321084), (8320736, 'bpl', 8320800), (8320792, 'b', 8320820), (8320816, 'b', 8320820), (8320880, 'bpl', 8320972), (8320960, 'b', 8320996), (8320992, 'b', 8320996), (8321084, 'b', 8321984), (8321140, 'bpl', 8321560), (8321196, 'bpl', 8321260), (8321256, 'b', 8321284), (8321280, 'b', 8321284), (8321352, 'bpl', 8321436), (8321432, 'b', 8321460), (8321456, 'b', 8321460), (8321552, 'b', 8321980), (8321612, 'bpl', 8321684), (8321672, 'b', 8321708), (8321704, 'b', 8321708), (8321776, 'bpl', 8321864), (8321856, 'b', 8321888), (8321884, 'b', 8321888), (8321980, 'b', 8321984), (8322232, 'bpl', 8322296), (8322292, 'b', 8322320), (8322316, 'b', 8322320), (8322388, 'bpl', 8322484), (8322468, 'b', 8322508), (8322504, 'b', 8322508), (8322828, 'bpl', 8322892), (8322888, 'b', 8322916), (8322912, 'b', 8322916), (8322984, 'bpl', 8323084), (8323064, 'b', 8323108), (8323104, 'b', 8323108), (8323416, 'bpl', 8323480), (8323476, 'b', 8323504), (8323500, 'b', 8323504), (8323572, 'bpl', 8323656), (8323652, 'b', 8323680), (8323676, 'b', 8323680), (8323928, 'bpl', 8324000), (8323988, 'b', 8324024), (8324020, 'b', 8324024), (8324092, 'bpl', 8324192), (8324172, 'b', 8324216), (8324212, 'b', 8324216), (8324464, 'bpl', 8324752), (8324520, 'bpl', 8324584), (8324580, 'b', 8324608), (8324604, 'b', 8324608), (8324744, 'b', 8324972), (8324804, 'bpl', 8324868), (8324864, 'b', 8324892), (8324888, 'b', 8324892), (8325304, 'bpl', 8325744), (8325360, 'bpl', 8325428), (8325420, 'b', 8325452), (8325448, 'b', 8325452), (8325520, 'bpl', 8325608), (8325600, 'b', 8325632), (8325628, 'b', 8325632), (8325740, 'b', 8326180), (8325796, 'bpl', 8325860), (8325856, 'b', 8325884), (8325880, 'b', 8325884), (8325952, 'bpl', 8326048), (8326032, 'b', 8326072), (8326068, 'b', 8326072), (8326356, 'bpl', 8326804), (8326412, 'bpl', 8326488), (8326472, 'b', 8326512), (8326508, 'b', 8326512), (8326580, 'bpl', 8326668), (8326660, 'b', 8326692), (8326688, 'b', 8326692), (8326800, 'b', 8327240), (8326856, 'bpl', 8326920), (8326916, 'b', 8326944), (8326940, 'b', 8326944), (8327012, 'bpl', 8327108), (8327092, 'b', 8327132), (8327128, 'b', 8327132), (8327416, 'bpl', 8327844), (8327472, 'bpl', 8327536), (8327532, 'b', 8327560), (8327556, 'b', 8327560), (8327628, 'bpl', 8327712), (8327708, 'b', 8327736), (8327732, 'b', 8327736), (8327828, 'b', 8328236), (8327896, 'bpl', 8327956), (8327952, 'b', 8327976), (8327972, 'b', 8327976), (8328036, 'bpl', 8328132), (8328112, 'b', 8328152), (8328148, 'b', 8328152), (8328404, 'bpl', 8328772), (8328460, 'bpl', 8328524), (8328516, 'b', 8328544), (8328540, 'b', 8328544), (8328604, 'bpl', 8328688), (8328680, 'b', 8328708), (8328704, 'b', 8328708), (8328768, 'b', 8329144), (8328824, 'bpl', 8328884), (8328880, 'b', 8328904), (8328900, 'b', 8328904), (8328964, 'bpl', 8329068), (8329040, 'b', 8329088), (8329084, 'b', 8329088), (8329248, 'bne', 8330412), (8329332, 'bpl', 8329720), (8329388, 'bpl', 8329448), (8329444, 'b', 8329468), (8329464, 'b', 8329468), (8329528, 'bpl', 8329608), (8329604, 'b', 8329628), (8329624, 'b', 8329628), (8329712, 'b', 8329768), (8329936, 'bpl', 8330304), (8329992, 'bpl', 8330052), (8330048, 'b', 8330072), (8330068, 'b', 8330072), (8330132, 'bpl', 8330216), (8330208, 'b', 8330236), (8330232, 'b', 8330236), (8330292, 'b', 8330348), (8330400, 'b', 8331592), (8330492, 'bpl', 8330892), (8330548, 'bpl', 8330608), (8330604, 'b', 8330628), (8330624, 'b', 8330628), (8330688, 'bpl', 8330768), (8330764, 'b', 8330788), (8330784, 'b', 8330788), (8330888, 'b', 8330936), (8331104, 'bpl', 8331496), (8331160, 'bpl', 8331232), (8331216, 'b', 8331252), (8331248, 'b', 8331252), (8331312, 'bpl', 8331392), (8331388, 'b', 8331412), (8331408, 'b', 8331412), (8331492, 'b', 8331540), (8331672, 'bpl', 8332004), (8331728, 'bpl', 8331788), (8331784, 'b', 8331808), (8331804, 'b', 8331808), (8331868, 'bpl', 8331948), (8331944, 'b', 8331968), (8331964, 'b', 8331968), (8332000, 'b', 8332348), (8332056, 'bpl', 8332124), (8332112, 'b', 8332144), (8332140, 'b', 8332144), (8332204, 'bpl', 8332296), (8332280, 'b', 8332316), (8332312, 'b', 8332316), (8332564, 'bpl', 8333392), (8332600, 'beq', 8332988), (8332656, 'bpl', 8332720), (8332712, 'b', 8332740), (8332736, 'b', 8332740), (8332800, 'bpl', 8332880), (8332876, 'b', 8332900), (8332896, 'b', 8332900), (8332984, 'b', 8333384), (8333040, 'bpl', 8333108), (8333096, 'b', 8333128), (8333124, 'b', 8333128), (8333188, 'bpl', 8333280), (8333264, 'b', 8333300), (8333296, 'b', 8333300), (8333384, 'b', 8333776), (8333444, 'bpl', 8333504), (8333500, 'b', 8333524), (8333520, 'b', 8333524), (8333584, 'bpl', 8333672), (8333660, 'b', 8333692), (8333688, 'b', 8333692), (8333944, 'bpl', 8334712), (8333980, 'beq', 8334352), (8334036, 'bpl', 8334100), (8334092, 'b', 8334120), (8334116, 'b', 8334120), (8334180, 'bpl', 8334260), (8334256, 'b', 8334280), (8334276, 'b', 8334280), (8334340, 'b', 8334708), (8334404, 'bpl', 8334472), (8334460, 'b', 8334492), (8334488, 'b', 8334492), (8334552, 'bpl', 8334632), (8334628, 'b', 8334652), (8334648, 'b', 8334652), (8334708, 'b', 8335072), (8334764, 'bpl', 8334824), (8334820, 'b', 8334844), (8334840, 'b', 8334844), (8334904, 'bpl', 8334996), (8334980, 'b', 8335016), (8335012, 'b', 8335016), (8335240, 'bpl', 8335648), (8335276, 'beq', 8335648), (8335332, 'bpl', 8335396), (8335388, 'b', 8335416), (8335412, 'b', 8335416), (8335476, 'bpl', 8335556), (8335552, 'b', 8335576), (8335572, 'b', 8335576), (8335632, 'b', 8336024), (8335700, 'bpl', 8335760), (8335756, 'b', 8335780), (8335776, 'b', 8335780), (8335840, 'bpl', 8335920), (8335916, 'b', 8335940), (8335936, 'b', 8335940), (8336192, 'bpl', 8336600), (8336248, 'bpl', 8336312), (8336304, 'b', 8336332), (8336328, 'b', 8336332), (8336392, 'bpl', 8336488), (8336468, 'b', 8336508), (8336504, 'b', 8336508), (8336592, 'b', 8336984), (8336652, 'bpl', 8336716), (8336708, 'b', 8336736), (8336732, 'b', 8336736), (8336796, 'bpl', 8336876), (8336872, 'b', 8336896), (8336892, 'b', 8336896)],
        semantics=('LoadWorldUI -[windowInfoChanged:] @0x007ee100 (5492 words, 83 calls, 286 branches; census) - the single whole-screen re-layout routine of the world-card UI. It stores the incoming \'^{WindowInfo=ffffffff}\' pointer into self->windowInfo@8 and then recomputes the frame of every subview from the WindowInfo float fields, building each CGRect with the detached 4-float helper at 0x007ed878. PROLOGUE / FRAME (0x7ee100-0x7ee14c): push {r4,r5,r6,r7,r8,sl,fp,lr}; add fp,sp,#0x18; sub sp,#0x2b8; sub sp,#0x800 -> 0xab8 (2744) bytes of locals. PIC base 0x0105faf4 computed from the cell 0x007ef05c (+pc 0x007ee114); self/_cmd/WindowInfo* spilled to [fp,-0x20]/-0x24/-0x28; the body opens with \'ldr &OBJC_IVAR windowInfo@8; add self+8; str arg,[r0]\' i.e. the WindowInfo pointer is stored, then the loop counter [fp,-0x2c]=0 and the base cached at [fp,-0x1f4] (reloaded 192x inside the body; self is reloaded from [fp,-0x20] 229x). SEND TABLE (83 calls, every target resolved; the only selectors in the body are count, objectAtIndex:, setFrame:, setString:): 52 x \'bl 0x007ed878\' = pack4(float a=r1, float b=r2, float c=r3, float d=[sp], float* out=r0), the 19-instruction leaf that stores 4 floats into out[0..0xc] (vmov s0/s2/s4 from r3/r2/r1, vldr s6 from [sp,#0x10], 4 vldr/vstr pairs, bx lr) - i.e. 52 CGRect constructions, each read back afterwards as the r2/r3 + 2 stack words of the -setFrame: call; 25 x \'bl loc.imp.objc_msgSend\' (PLT), all 25 of them -setFrame: sends (the setFrame: selref is reached through four different pool cells: 0x007ef3d4 x10, 0x007f13b8 x10, 0x007f3460 x1, 0x007f369c x4); 6 x register-cached \'blx rN\' = 4 x [self->blockheadPreviews count], 1 x [self->blockheadPreviews objectAtIndex:i], 1 x [self->hostNickNameTitleTextView setString:@"YOUR NICKNAME:"/"YOUR ALIAS:"]. No class references at all (0 classes), 26 distinct ivars touched. BRANCH SKELETON (286 branch instructions = 175 unconditional \'b\' + 111 conditional): 97 bpl + 8 bmi + 4 beq + 1 bne + 1 bhs are the conditional set, and 105 of those are float decisions - the canonical shape is \'vcmpe.f32 sA, sB; vmrs apsr_nzcv, fpscr; bpl/bmi\' where sB is a WindowInfo field and sA a pool float literal (415.0 or 48/160/256/80/226/40/208/400/16/0/-44/-50/-113, loaded 111x for 415.0 alone). Only five integer decisions exist: \'cmp r0,#4\' on self->state@40 at 0x7f181c, two \'ldrsb self->onlinePlayerIsOwner@144; cmp r0,#0\' gates at 0x7f2534 / 0x7f2fa8, and the loop-exit \'cmp i, [blockheadPreviews count]; bhs 0x7ee514\' at 0x7ee19c; exactly one backward branch exists - 0x7ee50c -> 0x7ee150, the preview loop. The 175 \'b\' instructions are join-to-merge branches (every element\'s 2-3 candidate frames funnel into one merge point before its send), which is why a void layout routine carries ~175 basic-block joins. BLOCK WALK, 4 regions. (1) 0x7ee150-0x7ee50c preview strip loop: exit test against [self->blockheadPreviews count]; per iteration preview = [self->blockheadPreviews objectAtIndex:i], then a three-tier device-size dispatch on the WindowInfo fields (vldr [windowInfo+4] / [+0xc] compared against the 415.0 literal): tier small (movw constants 0x5a=90, 0x2d=45, 0x78=120) rect = (x, -160.0, 240.0, 240.0); tier mid (0x50=80, 0x28=40, 0x6e=110) rect = (x, -100.0, 220.0, 220.0); tier large (0xa0=160, 0x50=80, 0xd2=210) rect = (x, -220.0, 420.0, 420.0); x = (base-(count-1))*step + i*base - offset evaluated in integer registers and converted with vmov/vcvt.f32.s32, packed to [fp,-0x40], then \'[preview setFrame:rect]\' at 0x7ee4fc via the PLT, i++ and \'b 0x7ee150\'. (2) 0x7ee514-0x7f17b8 the fixed element chain - one \'movw r0,#0x19f\' (415, the content-column width) per element, a few \'vldr\' of WindowInfo fields, 1-3 float compares, one pack4 and one setFrame:. Receivers in address order (each established from its OBJC_IVAR pool cell and its spill slot): playButton@20 (0x7ee6ec), optionsButton@24 (0x7eeaf4), backButton@48 (0x7eeea0), disabledTextView@56 (0x7ef14c), deleteWorldButton@52 (0x7ef4b0), worldNameTextView@80 (0x7efc34), worldNameButton@84 (0x7efe88), hostMultiButton@88 (0x7f0114), migrateToCustomButton@92 (0x7f0314), hostMultiLANButton@96 (0x7f052c), hostNickNameTitleTextView@100 (0x7f0810 frame, then 0x7f0874 -setString:), hostNickNameButton@104 (0x7f0c90), hostPicTextView@108 (0x7f10b4), hostPicButton@112 (0x7f1494), hostPvpTitleTextView@116 (0x7f1804), hostPvpButton@120 (0x7f1a90 and 0x7f1f20), hostNowButton@124 (0x7f2144), onlinePicTextView@128 (0x7f24d4), onlinePicButton@132 (0x7f2a38), onlineShareButton@136 (0x7f2f48), onlineOwnerPortalButton@140 (0x7f3300) and the closing packed rect -> 0x7f3688. (3) mode gates inside that chain: \'cmp r0,#4; bne 0x7f1cac\' on self->state@40 guards the whole PvP group (hostPvpTitleTextView@116 / hostPvpButton@120 / hostNowButton@124); \'ldrsb self->onlinePlayerIsOwner@144; beq\' twice (0x7f2538, 0x7f2fac) picks the owner/non-owner online layouts; the nickname title text is selected by \'vcmpe.f32\' + \'movw r2,#0; movmi r2,#1; movne r2,ip\' (0x7f0848-0x7f0864) between the two CFString literals and then sent with -setString: to hostNickNameTitleTextView@100. (4) EPILOGUE 0x7f368c: sub sp,fp,#0x18; pop {r4,r5,r6,r7,r8,sl,fp,pc} - the method has no early return. CONSTANT/IPC FEATURES: windowInfo is a 4-float struct (types ^{WindowInfo=ffffffff}); its fields are re-read 169 times inside this body (vldr [windowInfo+4] 81x, [+0xc] 73x, [+0] 10x, +8 never), always through the ivar cell (5 different GOT-backed cells: 0x007ef060, 0x007f0fbc, 0x007f2e90, 0x007f3020, 0x007f3694; windowInfo@8 alone is loaded 185x). Only two CFString literals exist in the whole 5492-word body: \'YOUR ALIAS:\' (cell 0x007f1760 -> 0x00f91898) and \'YOUR NICKNAME:\' (cell 0x007f1764 -> 0x00f918a8) - the layout itself is pure float arithmetic. Register-pressure census: every element\'s ivar pointer is spilled once into a per-element slot ladder (playButton fp-0x270, optionsButton -0x2cc, backButton -0x31c, disabledTextView -0x360, deleteWorldButton -0x3ac, worldNameTextView -0x478, worldNameButton -0x4bc, hostMultiButton -0x4f4, migrateToCustomButton -0x530, blockheadNamesTextView -0x24c; hostNickNameTitleTextView sp,0x524, hostNickNameButton sp,0x4a0, hostPicTextView sp,0x42c, hostPicButton sp,0x3c0, hostPvpTitleTextView sp,0x354, hostPvpButton sp,0x31c, hostNowButton sp,0x268, onlinePicTextView sp,0x200, onlinePicButton sp,0x168, onlineShareButton sp,0xd0, onlineOwnerPortalButton sp,0x68, state sp,0x35c, onlinePlayerIsOwner sp,0x1f4/0x15c/0xc4).'),
    ),
    dict(
        name='lwu_35',
        method='LoadWorldUI -[worldNameButton:]',
        types='v12@0:4@8',
        start=8413472,
        end=8414604,
        disasm='disasm_worldtileloader_lwu_35.txt',
        base_add=8413488,
        base_literal=8414600,
        boundary='ARM.exidx end 0x0080658c (listing bound); next ObjC IMP 0x0080658c LoadWorldUI -[hostNickNameButton:]',
        selectors={
                 0x806530: (15211376, 'show'),
                 0x806538: (15211440, 'setText:'),
                 0x80653c: (15211464, 'setDelegate:'),
                 0x806540: (15211520, 'setReturnKeyType:'),
                 0x806544: (15211516, 'setKeyboardType:'),
                 0x806548: (15211512, 'setEnablesReturnKeyAutomatically:'),
                 0x80654c: (15211508, 'setAutocorrectionType:'),
                 0x806550: (15211444, 'textFieldAtIndex:'),
                 0x806554: (15211504, 'setAlertViewStyle:'),
                 0x806564: (15211500, 'initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:'),
                 0x806568: (15211120, 'alloc'),
                 0x806570: (15211196, 'release'),
                 0x806574: (15211348, 'uppercaseString'),
                 0x80657c: (15211224, 'objectForKey:'),
        },
        imports={
                 0x80652c: (17151904, 'objc_msgSend'),
                 0x806558: (16325640, '__CFConstantStringClassReference'),
                 0x80655c: (16325656, '__CFConstantStringClassReference'),
                 0x806560: (16325672, '__CFConstantStringClassReference'),
                 0x806578: (16325336, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x806534: (17161036, 'OBJC_IVAR_$_LoadWorldUI.textEntryAlertView', 64),
                 0x806580: (17160996, 'OBJC_IVAR_$_LoadWorldUI.gameSave', 36),
                 0x806584: (17161044, 'OBJC_IVAR_$_LoadWorldUI.textEntryType', 44),
        },
        classes={
                 0x80656c: (15247300, 'OBJC_CLASS_$_UIAlertView'),
        },
        instructions=[(8413472, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8414600, 'strheq sb, [r5], ip')],
        calls=[(8413944, 'blx ip'), (8413960, 'blx r2'), (8414004, 'blx r3'), (8414024, 'blx r3'), (8414064, 'blx r3'), (8414100, 'blx r3'), (8414132, 'blx r3'), (8414200, 'blx r6'), (8414256, 'blx r3'), (8414296, 'blx r3'), (8414324, 'blx r3'), (8414352, 'blx r3'), (8414376, 'blx r3'), (8414400, 'blx r3'), (8414436, 'blx r3'), (8414460, 'blx r3'), (8414496, 'blx r3')],
        branches=[],
        semantics=('LoadWorldUI -[worldNameButton:] @0x00806120 (283 words, 0 branches, 17 calls): opens the "Name" text-entry alert to rename the selected world. It is branch-free - the old alert is torn down with nil-tolerant sends (send to nil if unset). Sequence: self->textEntryType@44 = 0; then oldField = [self->textEntryAlertView@64 textFieldAtIndex:0] (all 17 sends are blx through register-cached objc_msgSend); [oldField setDelegate:nil]; [self->textEntryAlertView setDelegate:nil]; [self->textEntryAlertView release]; a = [[UIAlertView alloc] initWithTitle:@"Name" message:nil delegate:self cancelButtonTitle:@"Cancel" otherButtonTitles:@"Done", nil] (class cell 0x0080656c; strings 0x00f91c08/0x00f91c18/0x00f91c28; args marshalled r2=Name, r3=nil, [sp]=self, [sp+4]=Cancel, [sp+8]=Done, [sp+0xc]=nil); self->textEntryAlertView = a; [a setAlertViewStyle:2] (plain-text input); f = [a textFieldAtIndex:0]; [f setAutocorrectionType:1]; [f setEnablesReturnKeyAutomatically:sxtb(1)]; [f setKeyboardType:1]; [f setReturnKeyType:9] (the movw 9 constant lives at [fp,-0x34]); [f setDelegate:self]; [f setText:[[self->gameSave@36 objectForKey:@"worldName"] uppercaseString]]; [a show]. Base T=pc+0x8599bc=0x0105faf4.'),
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
        'batch': 'LoadWorldUI (E157): the load-world screen; 36 bodies',
        'claim': ('\'the load-world screen surface (the world-card list, the play/delete/host/migrate button row, the naming text field and the alert routing); the world-load pipeline behind the play button is outside these bodies\''),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'loadworldui.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale loadworldui.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
