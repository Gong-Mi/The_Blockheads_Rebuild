#!/usr/bin/env python3
"""Hash-gated recovery of the InteractionObject (E146).

InteractionObject lands: the batch sweeps interactionobject surface:
33 bodies, 2146 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/INTERACTIONOBJECT.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
}

SPECS = [
    dict(
        name='io_00',
        method='InteractionObject -[actionTitle]',
        types='@8@0:4',
        start=6252344,
        end=6252420,
        disasm='disasm_worldtileloader_io_00.txt',
        base_add=6252360,
        base_literal=6252416,
        boundary='ARM.exidx end 0x005f6784 (listing bound); next ObjC IMP 0x005f6784 InteractionObject -[remoteUpdate:]',
        selectors={
                 0x5f677c: (15198940, 'title'),
        },
        imports={
                 0x5f6778: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6252344, 'push {fp, lr}'), (6252416, 'adceq sb, r6, r4, lsr 7')],
        calls=[(6252396, 'blx r3')],
        branches=[],
        semantics=('[InteractionObject -[actionTitle]] (imp 0x005f6738, 19w): -[actionTitle] (0x5f6738, 19w): `return [self title]` - a single objc_msgSend forwarding to the \'title\' selref (cell 0x5f677c); the base-class action title is just the title..\n'),
    ),
    dict(
        name='io_01',
        method='InteractionObject -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=6255644,
        end=6256020,
        disasm='disasm_worldtileloader_io_01.txt',
        base_add=6255660,
        base_literal=6256016,
        boundary='ARM.exidx end 0x005f7594 (listing bound); next ObjC IMP 0x005f7594 InteractionObject -[isPaintable]',
        selectors={
                 0x5f7584: (15198844, 'release'),
                 0x5f758c: (15198928, 'remove:'),
        },
        imports={
                 0x5f7580: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f7574: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5f7578: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x5f757c: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x5f7588: (17156820, 'OBJC_IVAR_$_InteractionObject.needsToBeRemovedWhenInteractionEnds', 96),
        },
        classes={},
        instructions=[(6255644, 'push {r4, r5, r6, r7, fp, lr}'), (6256016, 'adceq r8, r6, r0, asr 13')],
        calls=[(6255812, 'blx r4'), (6255972, 'blx r3')],
        branches=[(6255712, 'bne', 6255980), (6255888, 'bne', 6255976), (6255924, 'beq', 6255976), (6255976, 'b', 6255980)],
        semantics=('[InteractionObject -[blockheadUnloaded:]] (imp 0x005f741c, 94w): -[blockheadUnloaded:] (0x5f741c, 94w): `if (bh == self.currentBlockhead@56) { [self.currentBlockhead release]; self.currentBlockhead = nil; self.isInUse@68 = NO; if (!self.isNet@52 && self.needsToBeRemovedWhenInteractionEnds@96) [self remove:0]; }` - no [super blockheadUnloaded:]; compare is raw pointer equality against the arg..\n'),
    ),
    dict(
        name='io_02',
        method='InteractionObject -[blockheadWouldLikeToTakeOwnership:withSaveDict:]',
        types='v16@0:4@8@12',
        start=6254588,
        end=6255380,
        disasm='disasm_worldtileloader_io_02.txt',
        base_add=6254604,
        base_literal=6255376,
        boundary='ARM.exidx end 0x005f7314 (listing bound); next ObjC IMP 0x005f7314 InteractionObject -[setPaused:]',
        selectors={
                 0x5f72d4: (15198792, 'retain'),
                 0x5f72d8: (15198844, 'release'),
                 0x5f72e0: (15198848, 'setInteractionObject:'),
                 0x5f72f4: (15198920, 'objectType'),
                 0x5f72f8: (15198924, 'dynamicWorldChangedAtPos:objectType:'),
                 0x5f72fc: (15198916, 'childNeedsSaving:'),
                 0x5f7300: (15198956, 'blockhead:tookOwnershipOfInteractionObject:'),
                 0x5f7304: (15198952, 'uiManager'),
        },
        imports={
                 0x5f72d0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f72cc: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5f72dc: (17156832, 'OBJC_IVAR_$_InteractionObject.proxyObjectOwner', 92),
                 0x5f72e4: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x5f72e8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5f72f0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5f7308: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x5f730c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(6254588, 'push {r4, r5, r6, sl, fp, lr}'), (6255376, 'adceq r8, r6, r0, ror 21')],
        calls=[(6254780, 'blx r2'), (6254800, 'blx r2'), (6254932, 'blx r3'), (6255036, 'blx r3'), (6255124, 'bl loc.imp.objc_msgSend'), (6255160, 'bl loc.imp.objc_msgSend'), (6255272, 'blx ip'), (6255296, 'blx ip')],
        branches=[(6254660, 'bne', 6255300), (6254700, 'beq', 6254824), (6254964, 'beq', 6255044), (6255040, 'b', 6255164)],
        semantics=('[InteractionObject -[blockheadWouldLikeToTakeOwnership:withSaveDict:]] (imp 0x005f6ffc, 198w): -[blockheadWouldLikeToTakeOwnership:withSaveDict:] (0x5f6ffc, 198w): `if (self.currentBlockhead != nil) return;` then `if (self.currentBlockhead != bh) { [currentBlockhead release]; currentBlockhead = [bh retain]; }`; `self.isInUse = YES`; `[self.currentBlockhead setInteractionObject:self]`; `if (self.proxyObjectOwner@92) [proxyObjectOwner childNeedsSaving:self]; else [[self.dynamicWorld@8] dynamicWorldChangedAtPos:self.pos@16 objectType:[self objectType]]` (objectType passed as stack arg); `self.updateNeedsToBeSent@49 = 1`; `[[self.world@4 uiManager] blockhead:bh tookOwnershipOfInteractionObject:self]`. The saveDict arg (r3) is stored on the stack but never read in the body..\n'),
    ),
    dict(
        name='io_03',
        method='InteractionObject -[blockheadsLoaded]',
        types='v8@0:4',
        start=6245708,
        end=6246584,
        disasm='disasm_worldtileloader_io_03.txt',
        base_add=6245724,
        base_literal=6246580,
        boundary='ARM.exidx end 0x005f50b8 (listing bound); next ObjC IMP 0x005f50b8 InteractionObject -[getSaveDict]',
        selectors={
                 0x5f5088: (15198832, 'blockheads'),
                 0x5f5090: (15198836, 'count'),
                 0x5f5094: (15198840, 'objectAtIndex:'),
                 0x5f509c: (15198792, 'retain'),
                 0x5f50a0: (15198844, 'release'),
                 0x5f50a8: (15198848, 'setInteractionObject:'),
        },
        imports={
                 0x5f5084: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f5080: (17156828, 'OBJC_IVAR_$_InteractionObject.savedBlockheadIndex', 80),
                 0x5f508c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5f5098: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5f50a4: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x5f50ac: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
        },
        classes={},
        instructions=[(6245708, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6246580, 'umlaleq sl, r6, r0, sp')],
        calls=[(6245836, 'blx r2'), (6245940, 'blx r2'), (6246052, 'blx r3'), (6246176, 'blx r2'), (6246216, 'blx r3'), (6246232, 'blx r2'), (6246392, 'blx r3')],
        branches=[(6245768, 'beq', 6246400), (6245868, 'blt', 6246260), (6245952, 'bhs', 6246260), (6246064, 'beq', 6246256), (6246256, 'b', 6246260), (6246320, 'beq', 6246396), (6246396, 'b', 6246400), (6246436, 'bne', 6246520), (6246480, 'bne', 6246520), (6246484, 'b', 6246488)],
        semantics=('[InteractionObject -[blockheadsLoaded]] (imp 0x005f4d4c, 219w): -[blockheadsLoaded] (0x5f4d4c, 219w): `if (self.savedBlockheadIndex@80 != -1) { NSArray* bl = [self.dynamicWorld blockheads]; NSInteger i = self.savedBlockheadIndex; if (i >= 0 && i < (NSInteger)[bl count]) { Blockhead* b = [bl objectAtIndex:i]; if (self.currentBlockhead != b) { [currentBlockhead release]; currentBlockhead = [[bl objectAtIndex:i] retain]; } } self.savedBlockheadIndex = -1; if (self.isInUse) [self.currentBlockhead setInteractionObject:self]; }` then `if (self.currentBlockhead == nil && self.remoteBlockheadInUseUniqueID@72 == 0) self.isInUse = NO;` - resolves the pending blockhead index once the world\'s blockheads exist, then drops the stale in-use flag..\n'),
    ),
    dict(
        name='io_04',
        method='InteractionObject -[canBeUsedByBlockhead:]',
        types='c12@0:4@8',
        start=6254404,
        end=6254560,
        disasm='disasm_worldtileloader_io_04.txt',
        base_add=6254416,
        base_literal=6254556,
        boundary='ARM.exidx end 0x005f6fe0 (listing bound); next ObjC IMP 0x005f6fe0 InteractionObject -[canBeUsedInExpertModeWhenNotOwned]',
        selectors={},
        imports={},
        ivars={
                 0x5f6fd4: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x5f6fd8: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={},
        instructions=[(6254404, 'push {fp, lr}'), (6254556, 'umlaleq r8, r6, ip, fp')],
        calls=[],
        branches=[(6254472, 'beq', 6254524)],
        semantics=('[InteractionObject -[canBeUsedByBlockhead:]] (imp 0x005f6f44, 39w): -[canBeUsedByBlockhead:] (0x5f6f44, 39w): `return self.isInUse@68 ? (self.currentBlockhead@56 == bh) : YES` - default is YES while not in use; when in use only the blockhead currently holding it may use it (cmp/moveq pair on the two ivars)..\n'),
    ),
    dict(
        name='io_05',
        method='InteractionObject -[canBeUsedInExpertModeWhenNotOwned]',
        types='c8@0:4',
        start=6254560,
        end=6254588,
        disasm='disasm_worldtileloader_io_05.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f6ffc (listing bound); next ObjC IMP 0x005f6ffc InteractionObject -[blockheadWouldLikeToTakeOwnership:withSaveDict:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6254560, 'sub sp, sp, 8'), (6254584, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[canBeUsedInExpertModeWhenNotOwned]] (imp 0x005f6fe0, 7w): -[canBeUsedInExpertModeWhenNotOwned] (0x5f6fe0, 7w): `return YES` (movw r2,1; sxtb). Base class allows expert-mode use when not owned; subclasses override..\n'),
    ),
    dict(
        name='io_06',
        method='InteractionObject -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=6249456,
        end=6249540,
        disasm='disasm_worldtileloader_io_06.txt',
        base_add=6249472,
        base_literal=6249536,
        boundary='ARM.exidx end 0x005f5c44 (listing bound); next ObjC IMP 0x005f5c44 InteractionObject -[dealloc]',
        selectors={
                 0x5f5c3c: (15198904, 'updateNetDataForClient:'),
        },
        imports={
                 0x5f5c38: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6249456, 'push {fp, lr}'), (6249536, 'adceq sb, r6, ip, ror 29')],
        calls=[(6249516, 'blx ip')],
        branches=[],
        semantics=('[InteractionObject -[creationNetDataForClient:]] (imp 0x005f5bf0, 21w): -[creationNetDataForClient:] (0x5f5bf0, 21w): `return [self updateNetDataForClient:client]` - pure forward (sel 0x5f5c3c), client arg passed through unchanged..\n'),
    ),
    dict(
        name='io_07',
        method='InteractionObject -[currentBlockhead]',
        types='@8@0:4',
        start=6256116,
        end=6256184,
        disasm='disasm_worldtileloader_io_07.txt',
        base_add=6256140,
        base_literal=6256180,
        boundary='ARM.exidx end 0x005f7638 (listing bound); next ObjC IMP 0x005f7638 InteractionObject -[isInUse]',
        selectors={},
        imports={},
        ivars={
                 0x5f7630: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={},
        instructions=[(6256116, 'sub sp, sp, 0xc'), (6256180, 'adceq r8, r6, r0, ror 9')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[currentBlockhead]] (imp 0x005f75f4, 17w): -[currentBlockhead] (0x5f75f4, 17w): `return self.currentBlockhead@56` - plain ivar getter (\'@\', Apportable offset-cell load with the dmb ish barrier of the O0 getter pattern)..\n'),
    ),
    dict(
        name='io_08',
        method='InteractionObject -[dealloc]',
        types='v8@0:4',
        start=6249540,
        end=6249928,
        disasm='disasm_worldtileloader_io_08.txt',
        base_add=6249556,
        base_literal=6249924,
        boundary='ARM.exidx end 0x005f5dc8 (listing bound); next ObjC IMP 0x005f5dc8 InteractionObject -[requiresPhysicalBlock]',
        selectors={
                 0x5f5da4: (15198908, 'dealloc'),
                 0x5f5db0: (15198844, 'release'),
                 0x5f5db8: (15198848, 'setInteractionObject:'),
        },
        imports={
                 0x5f5da0: (17151900, 'objc_msgSendSuper2'),
                 0x5f5dac: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f5db4: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5f5dbc: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0x5f5dc0: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0x5f5da8: (15252584, 'OBJC_CLASS_$_InteractionObject'),
        },
        instructions=[(6249540, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6249924, 'umlaleq sb, r6, r8, lr')],
        calls=[(6249724, 'blx r6'), (6249760, 'blx r3'), (6249800, 'blx r3'), (6249836, 'blx r3'), (6249876, 'blx r2')],
        branches=[],
        semantics=('[InteractionObject -[dealloc]] (imp 0x005f5c44, 97w): -[dealloc] (0x5f5c44, 97w): `[self.ownerID@36 release]; [self.ownerName@84 release]; [self.currentBlockhead@56 release];` then `objc_msgSendSuper2(&super{self, InteractionObject}, @selector(dealloc))`. proxyObjectOwner@92 / savedBlockheadIndex / shader / texture are NOT touched and no ivar is nil-ed..\n'),
    ),
    dict(
        name='io_09',
        method='InteractionObject -[destroyItemType]',
        types='i8@0:4',
        start=6252064,
        end=6252092,
        disasm='disasm_worldtileloader_io_09.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f6674; body trimmed at the next IMP 0x005f663c InteractionObject -[twoBlocksWide]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6252064, 'sub sp, sp, 8'), (6252088, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[destroyItemType]] (imp 0x005f6620, 7w): -[destroyItemType] (0x5f6620, 7w): `return 0` (movw r2,0; mov r0,r2). Default \'no item dropped on destroy\'; subclasses override with a real item type..\n'),
    ),
    dict(
        name='io_10',
        method='InteractionObject -[flipped]',
        types='c8@0:4',
        start=6256244,
        end=6256304,
        disasm='disasm_worldtileloader_io_10.txt',
        base_add=6256252,
        base_literal=6256300,
        boundary='ARM.exidx end 0x005f76b0 (listing bound); next ObjC IMP 0x005f76b0 InteractionObject -[ownerName]',
        selectors={},
        imports={},
        ivars={
                 0x5f76a8: (17156824, 'OBJC_IVAR_$_InteractionObject.flipped', 69),
        },
        classes={},
        instructions=[(6256244, 'sub sp, sp, 8'), (6256300, 'adceq r8, r6, r0, ror r4')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[flipped]] (imp 0x005f7674, 15w): -[flipped] (0x5f7674, 15w): `return self.flipped@69` (ldrsb BOOL)..\n'),
    ),
    dict(
        name='io_11',
        method='InteractionObject -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]',
        types='@48@0:4@8@12{?=ii}16@24@28c32@36@40@44',
        start=6242868,
        end=6243892,
        disasm='disasm_worldtileloader_io_11.txt',
        base_add=6242884,
        base_literal=6243888,
        boundary='ARM.exidx end 0x005f4634 (listing bound); next ObjC IMP 0x005f4634 InteractionObject -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x5f4600: (15198788, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0x5f4610: (15198792, 'retain'),
                 0x5f4618: (15198796, 'objectForKey:'),
                 0x5f4628: (15198800, 'unsignedIntValue'),
        },
        imports={
                 0x5f460c: (17151904, 'objc_msgSend'),
                 0x5f4614: (16245192, '__CFConstantStringClassReference'),
                 0x5f461c: (16245208, '__CFConstantStringClassReference'),
                 0x5f462c: (16245224, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5f4604: (17156824, 'OBJC_IVAR_$_InteractionObject.flipped', 69),
                 0x5f4608: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0x5f4620: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x5f4624: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
        },
        classes={
                 0x5f45f8: (15252584, 'OBJC_CLASS_$_InteractionObject'),
        },
        instructions=[(6242868, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6243888, 'adceq fp, r6, r8, lsr 17')],
        calls=[(6243108, 'bl loc.imp.objc_msgSendSuper2'), (6243244, 'blx r2'), (6243356, 'blx lr'), (6243372, 'blx r2'), (6243456, 'blx r2'), (6243544, 'blx r3'), (6243644, 'blx lr'), (6243660, 'blx r2'), (6243772, 'blx lr'), (6243788, 'blx r2')],
        branches=[(6243136, 'bne', 6243152), (6243148, 'b', 6243820), (6243196, 'beq', 6243272), (6243268, 'b', 6243396), (6243408, 'beq', 6243484), (6243480, 'b', 6243688), (6243556, 'beq', 6243684), (6243684, 'b', 6243688)],
        semantics=('[InteractionObject -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]] (imp 0x005f4234, 256w): -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:] (0x5f4234, 256w; types @48@0:4@8@12{?=ii}16@24@28c32@36@40@44): super2 initWithWorld:dynamicWorld:atPosition:cache: (atPosition as 2 stack words, cache 3rd); nil result -> nil. Then `self.flipped@69 = flipped`; `self.ownerName@84 = clientName ? [clientName retain] : [[saveDict objectForKey:@"ownerName" (CF 0xF7E1C8)] retain]`; `self.ownerID@36 = placedByClient ? [placedByClient retain] : (x = [saveDict objectForKey:@"ownerID" (CF 0xF7E1D8)]) ? [x retain] : leave`; `self.paintColor@88 = (u16)[[saveDict objectForKey:@"paintColor" (CF 0xF7E1E8)] unsignedIntValue]`. Placement path ctor: the three save-dict keys are literal CFStrings resolved from the PIC pool..\n'),
    ),
    dict(
        name='io_12',
        method='InteractionObject -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=6245300,
        end=6245708,
        disasm='disasm_worldtileloader_io_12.txt',
        base_add=6245316,
        base_literal=6245704,
        boundary='ARM.exidx end 0x005f4d4c (listing bound); next ObjC IMP 0x005f4d4c InteractionObject -[blockheadsLoaded]',
        selectors={
                 0x5f4d28: (15198824, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x5f4d30: (15198828, 'getBytes:length:'),
        },
        imports={
                 0x5f4d24: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x5f4d38: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x5f4d3c: (17156824, 'OBJC_IVAR_$_InteractionObject.flipped', 69),
                 0x5f4d40: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x5f4d44: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
        },
        classes={
                 0x5f4d2c: (15252584, 'OBJC_CLASS_$_InteractionObject'),
        },
        instructions=[(6245300, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6245704, 'adceq sl, r6, r8, lsr 30')],
        calls=[(6245448, 'blx r6'), (6245532, 'bl loc.imp.objc_msgSend')],
        branches=[(6245476, 'bne', 6245492), (6245488, 'b', 6245656)],
        semantics=('[InteractionObject -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x005f4bb4, 102w): -[initWithWorld:dynamicWorld:cache:netData:] (0x5f4bb4, 102w): super2 initWithWorld:dynamicWorld:cache:netData: (cache/netData on the stack); nil -> nil; then `[netData getBytes:buf length:0x28]` and applies the tail of InteractionObjectCreationNetData: `self.remoteBlockheadInUseUniqueID@72 = *(u64*)(buf+0x18)`; `self.isInUse@68 = buf[0x22]`; `self.flipped@69 = buf[0x23]`; `self.paintColor@88 = *(u16*)(buf+0x24)`. (buf = fp-0x58.) Net/remote-creation ctor; +0x20 interactionObjectType is NOT re-read here..\n'),
    ),
    dict(
        name='io_13',
        method='InteractionObject -[interactionObjectCreationNetData]',
        types='{InteractionObjectCreationNetData={DynamicObjectNetData=QIIC[7C]}QSCCS[2C]}8@0:4',
        start=6248640,
        end=6249232,
        disasm='disasm_worldtileloader_io_13.txt',
        base_add=6248656,
        base_literal=6249228,
        boundary='ARM.exidx end 0x005f5b10 (listing bound); next ObjC IMP 0x005f5b10 InteractionObject -[updateNetDataForClient:]',
        selectors={
                 0x5f5ae0: (15198888, 'dynamicObjectNetData'),
                 0x5f5af4: (15198872, 'interactionObjectType'),
                 0x5f5b08: (15198892, 'uniqueID'),
        },
        imports={
                 0x5f5af0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f5ae4: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x5f5ae8: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x5f5aec: (17156824, 'OBJC_IVAR_$_InteractionObject.flipped', 69),
                 0x5f5af8: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5f5afc: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
        },
        classes={},
        instructions=[(6248640, 'push {r4, r5, r6, sl, fp, lr}'), (6249228, 'adceq sl, r6, ip, lsl r2')],
        calls=[(6248724, 'bl loc.imp.objc_msgSend_stret'), (6248760, 'bl sym.imp.memset'), (6248852, 'bl sym.imp.memcpy'), (6248872, 'blx r2'), (6249056, 'bl loc.imp.objc_msgSend')],
        branches=[(6248708, 'beq', 6248732), (6248728, 'b', 6248764), (6248976, 'beq', 6249136), (6249016, 'beq', 6249072), (6249068, 'b', 6249116), (6249112, 'b', 6249116), (6249132, 'b', 6249156), (6249152, 'b', 6249156)],
        semantics=('[InteractionObject -[interactionObjectCreationNetData]] (imp 0x005f58c0, 148w): -[interactionObjectCreationNetData] (0x5f58c0, 148w, sret): fills the 0x28-byte InteractionObjectCreationNetData: `memcpy(dest, blob, 0x18)` where blob = [self dynamicObjectNetData] (stret 0x18; nil-guard memset 0x18); `*(u16*)(dest+0x20) = [self interactionObjectType]`; `dest+0x22 = self.isInUse@68`; `dest+0x23 = self.flipped@69`; `*(u16*)(dest+0x24) = self.paintColor@88`; `*(u64*)(dest+0x18) = self.isInUse ? (self.currentBlockhead ? [self.currentBlockhead uniqueID] : self.remoteBlockheadInUseUniqueID@72) : 0` (lo word at +0x18, hi at +0x1c). Writer side of the net blob; layout == tsv `{InteractionObjectCreationNetData={DynamicObjectNetData=QIIC[7C]}QSCCS[2C]}` = 0x28 bytes..\n'),
    ),
    dict(
        name='io_14',
        method='InteractionObject -[interactionObjectType]',
        types='S8@0:4',
        start=6252268,
        end=6252296,
        disasm='disasm_worldtileloader_io_14.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f6738; body trimmed at the next IMP 0x005f6708 InteractionObject -[title]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6252268, 'sub sp, sp, 8'), (6252292, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[interactionObjectType]] (imp 0x005f66ec, 7w): -[interactionObjectType] (0x5f66ec, 7w): `return 0` (uxth of movw r2,0). Default type 0; the real per-class type id comes from subclass overrides (the type feeds dest+0x20 in io_13)..\n'),
    ),
    dict(
        name='io_15',
        method='InteractionObject -[interactionRenderItemType]',
        types='i8@0:4',
        start=6252120,
        end=6252148,
        disasm='disasm_worldtileloader_io_15.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f6674 (listing bound); next ObjC IMP 0x005f6674 InteractionObject -[remove:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6252120, 'sub sp, sp, 8'), (6252144, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[interactionRenderItemType]] (imp 0x005f6658, 7w): -[interactionRenderItemType] (0x5f6658, 7w): `return 1` (movw r2,1; int). Default render item type 1; subclasses override..\n'),
    ),
    dict(
        name='io_16',
        method='InteractionObject -[isDoubleHeight]',
        types='c8@0:4',
        start=6252036,
        end=6252064,
        disasm='disasm_worldtileloader_io_16.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f6674; body trimmed at the next IMP 0x005f6620 InteractionObject -[destroyItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6252036, 'sub sp, sp, 8'), (6252060, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[isDoubleHeight]] (imp 0x005f6604, 7w): -[isDoubleHeight] (0x5f6604, 7w): `return NO` (sxtb of movw r2,0)..\n'),
    ),
    dict(
        name='io_17',
        method='InteractionObject -[isInUse]',
        types='c8@0:4',
        start=6256184,
        end=6256244,
        disasm='disasm_worldtileloader_io_17.txt',
        base_add=6256192,
        base_literal=6256240,
        boundary='ARM.exidx end 0x005f76b0; body trimmed at the next IMP 0x005f7674 InteractionObject -[flipped]',
        selectors={},
        imports={},
        ivars={
                 0x5f766c: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
        },
        classes={},
        instructions=[(6256184, 'sub sp, sp, 8'), (6256240, 'adceq r8, r6, ip, lsr 9')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[isInUse]] (imp 0x005f7638, 15w): -[isInUse] (0x5f7638, 15w): `return self.isInUse@68` (ldrsb BOOL)..\n'),
    ),
    dict(
        name='io_18',
        method='InteractionObject -[isPaintable]',
        types='c8@0:4',
        start=6256020,
        end=6256048,
        disasm='disasm_worldtileloader_io_18.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f75b0 (listing bound); next ObjC IMP 0x005f75b0 InteractionObject -[paint:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6256020, 'sub sp, sp, 8'), (6256044, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[isPaintable]] (imp 0x005f7594, 7w): -[isPaintable] (0x5f7594, 7w): `return NO` (sxtb of movw r2,0). Base objects are not paintable; paint: / paintColor exist for subclasses that override to YES..\n'),
    ),
    dict(
        name='io_19',
        method='InteractionObject -[ownerName]',
        types='@8@0:4',
        start=6256304,
        end=6256372,
        disasm='disasm_worldtileloader_io_19.txt',
        base_add=6256328,
        base_literal=6256368,
        boundary='ARM.exidx end 0x005f76f4 (listing bound); next ObjC IMP 0x005f9ae4 Sign -[objectType]',
        selectors={},
        imports={},
        ivars={
                 0x5f76ec: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
        },
        classes={},
        instructions=[(6256304, 'sub sp, sp, 0xc'), (6256368, 'adceq r8, r6, r4, lsr 8')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[ownerName]] (imp 0x005f76b0, 17w): -[ownerName] (0x5f76b0, 17w): `return self.ownerName@84` (plain \'@\' getter)..\n'),
    ),
    dict(
        name='io_20',
        method='InteractionObject -[paint:]',
        types='v12@0:4S8',
        start=6256048,
        end=6256116,
        disasm='disasm_worldtileloader_io_20.txt',
        base_add=6256056,
        base_literal=6256112,
        boundary='ARM.exidx end 0x005f7638; body trimmed at the next IMP 0x005f75f4 InteractionObject -[currentBlockhead]',
        selectors={},
        imports={},
        ivars={
                 0x5f75ec: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
        },
        classes={},
        instructions=[(6256048, 'sub sp, sp, 0xc'), (6256112, 'adceq r8, r6, r4, lsr r5')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[paint:]] (imp 0x005f75b0, 17w): -[paint:] (0x5f75b0, 17w): `self.paintColor@88 = paintColor` (tsv `v12@0:4S8`; strh of the unsigned-short arg, no other side effect, no super)..\n'),
    ),
    dict(
        name='io_21',
        method='InteractionObject -[remoteBlockheadRemovedWithID:]',
        types='v16@0:4Q8',
        start=6254052,
        end=6254376,
        disasm='disasm_worldtileloader_io_21.txt',
        base_add=6254068,
        base_literal=6254372,
        boundary='ARM.exidx end 0x005f6f28 (listing bound); next ObjC IMP 0x005f6f28 InteractionObject -[requiresHumanInteraction]',
        selectors={
                 0x5f6f1c: (15198928, 'remove:'),
        },
        imports={
                 0x5f6f18: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f6f04: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
                 0x5f6f0c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x5f6f10: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x5f6f14: (17156820, 'OBJC_IVAR_$_InteractionObject.needsToBeRemovedWhenInteractionEnds', 96),
        },
        classes={},
        instructions=[(6254052, 'push {fp, lr}'), (6254372, 'invalid')],
        calls=[(6254292, 'blx r3')],
        branches=[(6254140, 'bne', 6254332), (6254144, 'b', 6254148), (6254208, 'bne', 6254296), (6254244, 'beq', 6254296)],
        semantics=('[InteractionObject -[remoteBlockheadRemovedWithID:]] (imp 0x005f6de4, 81w): -[remoteBlockheadRemovedWithID:] (0x5f6de4, 81w; tsv `v16@0:4Q8`): 64-bit ID arg in r2(lo)/r3(hi); `if (*(u64*)&self.remoteBlockheadInUseUniqueID@72 == ID)` (XOR-pair compare via `ldr r1,[r0,r1]!` + `ldr r0,[r0,4]`) then: `self.isInUse@68 = NO`; `if (!self.isNet@52 && self.needsToBeRemovedWhenInteractionEnds@96) [self remove:0]`; `self.remoteBlockheadInUseUniqueID = 0` (two word stores); non-matching ID -> immediate return..\n'),
    ),
    dict(
        name='io_22',
        method='InteractionObject -[remoteUpdate:]',
        types='v12@0:4@8',
        start=6252420,
        end=6254052,
        disasm='disasm_worldtileloader_io_22.txt',
        base_add=6252436,
        base_literal=6254048,
        boundary='ARM.exidx end 0x005f6de4 (listing bound); next ObjC IMP 0x005f6de4 InteractionObject -[remoteBlockheadRemovedWithID:]',
        selectors={
                 0x5f6d88: (15198944, 'remoteUpdate:'),
                 0x5f6d98: (15198828, 'getBytes:length:'),
                 0x5f6da4: (15198892, 'uniqueID'),
                 0x5f6da8: (15198844, 'release'),
                 0x5f6dac: (15198948, 'stopInteracting'),
                 0x5f6db8: (15198884, 'countByEnumeratingWithState:objects:count:'),
                 0x5f6dbc: (15198832, 'blockheads'),
                 0x5f6dd8: (15198928, 'remove:'),
        },
        imports={
                 0x5f6d84: (17151900, 'objc_msgSendSuper2'),
                 0x5f6d94: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f6d90: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x5f6d9c: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5f6db0: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
                 0x5f6dc0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5f6dc8: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x5f6dd0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x5f6dd4: (17156820, 'OBJC_IVAR_$_InteractionObject.needsToBeRemovedWhenInteractionEnds', 96),
                 0x5f6ddc: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
        },
        classes={
                 0x5f6d8c: (15252584, 'OBJC_CLASS_$_InteractionObject'),
        },
        instructions=[(6252420, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6254048, 'adceq sb, r6, r8, asr r3')],
        calls=[(6252512, 'blx lr'), (6252580, 'blx ip'), (6252700, 'bl loc.imp.objc_msgSend'), (6252840, 'blx lr'), (6252876, 'blx r3'), (6253260, 'blx r2'), (6253284, 'bl sym.imp.memset'), (6253332, 'blx lr'), (6253432, 'bl sym.imp.objc_enumerationMutation'), (6253472, 'bl loc.imp.objc_msgSend'), (6253724, 'blx ip'), (6253912, 'blx r3')],
        branches=[(6252648, 'beq', 6252932), (6252660, 'beq', 6252932), (6252728, 'beq', 6252928), (6252732, 'b', 6252736), (6252928, 'b', 6252932), (6252964, 'beq', 6253760), (6253004, 'bne', 6253760), (6253072, 'bne', 6253144), (6253076, 'b', 6253080), (6253140, 'b', 6253756), (6253344, 'beq', 6253748), (6253424, 'beq', 6253436), (6253520, 'bne', 6253624), (6253524, 'b', 6253528), (6253624, 'b', 6253628), (6253652, 'blo', 6253388), (6253744, 'bne', 6253388), (6253748, 'b', 6253752), (6253752, 'b', 6253756), (6253756, 'b', 6253760), (6253792, 'bne', 6253916), (6253828, 'bne', 6253916), (6253864, 'beq', 6253916)],
        semantics=('[InteractionObject -[remoteUpdate:]] (imp 0x005f6784, 408w): -[remoteUpdate:] (0x5f6784, 408w): (1) super2 remoteUpdate:data; (2) `old = self.isInUse@68`; `[data getBytes:buf length:0x28]`; `self.isInUse = buf[+0x22]`; (3) `if (self.isInUse && old)`: if `[self.currentBlockhead uniqueID] != *(u64*)(buf+0x18)` then `[self.currentBlockhead stopInteracting]; [self.currentBlockhead release]; self.currentBlockhead = nil; self.isInUse = YES` (kick the local holder when the remote reports a different blockhead); (4) `if (self.isInUse && self.currentBlockhead == nil)`: `self.remoteBlockheadInUseUniqueID@72 = *(u64*)(buf+0x18)`; if 0 -> `{ isInUse = NO; updateNeedsToBeSent@49 = YES; }` else `for (Blockhead* b in [self.dynamicWorld blockheads]) if ([b uniqueID] == self.remoteBlockheadInUseUniqueID) { remoteBlockheadInUseUniqueID = 0; isInUse = NO; updateNeedsToBeSent = YES; }` (no break; NSFastEnumeration, 0x10-per-batch, state fp-0x88, objc_enumerationMutation guard); (5) tail: `if (!self.isInUse && !self.isNet && self.needsToBeRemovedWhenInteractionEnds) [self remove:0]`; (6) `self.paintColor@88 = *(u16*)(buf+0x24)` unconditionally. Blob fields read: +0x18 Q uniqueID, +0x22 isInUse, +0x24 paintColor (flipped/+0x20 type not applied by this reader)..\n'),
    ),
    dict(
        name='io_23',
        method='InteractionObject -[remove:]',
        types='v12@0:4@8',
        start=6252148,
        end=6252268,
        disasm='disasm_worldtileloader_io_23.txt',
        base_add=6252156,
        base_literal=6252264,
        boundary='ARM.exidx end 0x005f66ec (listing bound); next ObjC IMP 0x005f66ec InteractionObject -[interactionObjectType]',
        selectors={},
        imports={},
        ivars={
                 0x5f66e0: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x5f66e4: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
        },
        classes={},
        instructions=[(6252148, 'sub sp, sp, 0x10'), (6252264, 'adceq sb, r6, r0, ror r4')],
        calls=[],
        branches=[(6252204, 'bne', 6252244), (6252240, 'beq', 6252248), (6252244, 'b', 6252248)],
        semantics=('[InteractionObject -[remove:]] (imp 0x005f6674, 30w): -[remove:] (0x5f6674, 30w): compiled body = guards only: read `DynamicObject.needsRemoved@48` (if != 0 -> return) and `DynamicObject.isNet@52` (if == 0 -> return), empty tail - as compiled it has NO store and NO call (identical guard shape to Chest -[remove:] ce_32 0xcbd2ac, whose tail does the real tile removal; base is the stub, `[self remove:0]` is issued by io_01/io_21/io_22 under `!isNet && needsToBeRemovedWhenInteractionEnds`)..\n'),
    ),
    dict(
        name='io_24',
        method='InteractionObject -[requiresHumanInteraction]',
        types='c8@0:4',
        start=6254376,
        end=6254404,
        disasm='disasm_worldtileloader_io_24.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f6f44 (listing bound); next ObjC IMP 0x005f6f44 InteractionObject -[canBeUsedByBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6254376, 'sub sp, sp, 8'), (6254400, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[requiresHumanInteraction]] (imp 0x005f6f28, 7w): -[requiresHumanInteraction] (0x5f6f28, 7w): `return NO` (sxtb of movw r2,0)..\n'),
    ),
    dict(
        name='io_25',
        method='InteractionObject -[requiresPhysicalBlock]',
        types='c8@0:4',
        start=6249928,
        end=6249956,
        disasm='disasm_worldtileloader_io_25.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f5de4 (listing bound); next ObjC IMP 0x005f5de4 InteractionObject -[update:accurateDT:isSimulation:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6249928, 'sub sp, sp, 8'), (6249952, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[requiresPhysicalBlock]] (imp 0x005f5dc8, 7w): -[requiresPhysicalBlock] (0x5f5dc8, 7w): `return NO` (sxtb of movw r2,0)..\n'),
    ),
    dict(
        name='io_26',
        method='InteractionObject -[setPaused:]',
        types='v12@0:4c8',
        start=6255380,
        end=6255404,
        disasm='disasm_worldtileloader_io_26.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f732c (listing bound); next ObjC IMP 0x005f732c InteractionObject -[shouldAddToMacroBlock]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6255380, 'sub sp, sp, 0xc'), (6255400, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[setPaused:]] (imp 0x005f7314, 6w): -[setPaused:] (0x5f7314, 6w): `- (void)setPaused:(BOOL)p` - body stores the arg to the stack and returns; complete no-op (no ivar, no super). Hook subclasses override..\n'),
    ),
    dict(
        name='io_27',
        method='InteractionObject -[setProxyObjectOwner:]',
        types='v12@0:4@8',
        start=6255492,
        end=6255644,
        disasm='disasm_worldtileloader_io_27.txt',
        base_add=6255508,
        base_literal=6255640,
        boundary='ARM.exidx end 0x005f741c (listing bound); next ObjC IMP 0x005f741c InteractionObject -[blockheadUnloaded:]',
        selectors={
                 0x5f7410: (15198960, 'removeFromMacroBlock'),
        },
        imports={
                 0x5f740c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f7414: (17156832, 'OBJC_IVAR_$_InteractionObject.proxyObjectOwner', 92),
        },
        classes={},
        instructions=[(6255492, 'push {fp, lr}'), (6255640, 'adceq r8, r6, r8, asr r7')],
        calls=[(6255584, 'blx r2')],
        branches=[(6255540, 'beq', 6255588)],
        semantics=('[InteractionObject -[setProxyObjectOwner:]] (imp 0x005f7384, 38w): -[setProxyObjectOwner:] (0x5f7384, 38w): `if (owner != nil) [self removeFromMacroBlock]` (sel 0x5f7410); then `self.proxyObjectOwner@92 = owner` as a PLAIN store - no retain, no release of the previous value. Pair of io_28: assigning an owner takes the object out of the macro block..\n'),
    ),
    dict(
        name='io_28',
        method='InteractionObject -[shouldAddToMacroBlock]',
        types='c8@0:4',
        start=6255404,
        end=6255492,
        disasm='disasm_worldtileloader_io_28.txt',
        base_add=6255412,
        base_literal=6255488,
        boundary='ARM.exidx end 0x005f7384 (listing bound); next ObjC IMP 0x005f7384 InteractionObject -[setProxyObjectOwner:]',
        selectors={},
        imports={},
        ivars={
                 0x5f737c: (17156832, 'OBJC_IVAR_$_InteractionObject.proxyObjectOwner', 92),
        },
        classes={},
        instructions=[(6255404, 'sub sp, sp, 8'), (6255488, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[shouldAddToMacroBlock]] (imp 0x005f732c, 22w): -[shouldAddToMacroBlock] (0x5f732c, 22w): `return self.proxyObjectOwner@92 == nil` (load, cmp 0 / movne 1, eor 1, and 1, sxtb) - only proxy-free objects register into the macro block/tile data..\n'),
    ),
    dict(
        name='io_29',
        method='InteractionObject -[startInteractionWithBlockhead:]',
        types='v12@0:4@8',
        start=6251412,
        end=6252036,
        disasm='disasm_worldtileloader_io_29.txt',
        base_add=6251428,
        base_literal=6252032,
        boundary='ARM.exidx end 0x005f6604 (listing bound); next ObjC IMP 0x005f6604 InteractionObject -[isDoubleHeight]',
        selectors={
                 0x5f65d4: (15198792, 'retain'),
                 0x5f65d8: (15198844, 'release'),
                 0x5f65ec: (15198920, 'objectType'),
                 0x5f65f0: (15198924, 'dynamicWorldChangedAtPos:objectType:'),
                 0x5f65f4: (15198916, 'childNeedsSaving:'),
                 0x5f65f8: (15198848, 'setInteractionObject:'),
        },
        imports={
                 0x5f65d0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f65c8: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5f65cc: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x5f65dc: (17156832, 'OBJC_IVAR_$_InteractionObject.proxyObjectOwner', 92),
                 0x5f65e0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5f65e8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5f65fc: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(6251412, 'push {r4, r5, fp, lr}'), (6252032, 'adceq sb, r6, r8, asr 14')],
        calls=[(6251588, 'blx r2'), (6251608, 'blx r2'), (6251740, 'blx r3'), (6251828, 'bl loc.imp.objc_msgSend'), (6251864, 'bl loc.imp.objc_msgSend'), (6251964, 'blx r3')],
        branches=[(6251508, 'beq', 6251632), (6251668, 'beq', 6251748), (6251744, 'b', 6251868)],
        semantics=('[InteractionObject -[startInteractionWithBlockhead:]] (imp 0x005f6394, 156w): -[startInteractionWithBlockhead:] (0x5f6394, 156w): `self.isInUse@68 = YES`; `if (self.currentBlockhead != bh) { [currentBlockhead release]; currentBlockhead = [bh retain]; }`; `if (self.proxyObjectOwner@92) [proxyObjectOwner childNeedsSaving:self]; else [[self.dynamicWorld@8] dynamicWorldChangedAtPos:self.pos@16 objectType:[self objectType]]` (objectType stack arg); `self.updateNeedsToBeSent@49 = 1`; `[self.currentBlockhead setInteractionObject:self]`; returns void. Local-side begin-interaction (no nil-guard on currentBlockhead, unlike io_02)..\n'),
    ),
    dict(
        name='io_30',
        method='InteractionObject -[title]',
        types='@8@0:4',
        start=6252296,
        end=6252344,
        disasm='disasm_worldtileloader_io_30.txt',
        base_add=6252304,
        base_literal=6252340,
        boundary='ARM.exidx end 0x005f6738 (listing bound); next ObjC IMP 0x005f6738 InteractionObject -[actionTitle]',
        selectors={},
        imports={
                 0x5f6730: (16245320, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(6252296, 'sub sp, sp, 8'), (6252340, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[title]] (imp 0x005f6708, 12w): -[title] (0x5f6708, 12w): `return @""` - static CFString @0x00F7E248 (flags 0x7c8, len 0); the empty-string default that subclasses override (io_00 actionTitle forwards here)..\n'),
    ),
    dict(
        name='io_31',
        method='InteractionObject -[twoBlocksWide]',
        types='c8@0:4',
        start=6252092,
        end=6252120,
        disasm='disasm_worldtileloader_io_31.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f6674; body trimmed at the next IMP 0x005f6658 InteractionObject -[interactionRenderItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6252092, 'sub sp, sp, 8'), (6252116, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[InteractionObject -[twoBlocksWide]] (imp 0x005f663c, 7w): -[twoBlocksWide] (0x5f663c, 7w): `return NO` (sxtb of movw r2,0)..\n'),
    ),
    dict(
        name='io_32',
        method='InteractionObject -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=6249232,
        end=6249456,
        disasm='disasm_worldtileloader_io_32.txt',
        base_add=6249248,
        base_literal=6249452,
        boundary='ARM.exidx end 0x005f5c44; body trimmed at the next IMP 0x005f5bf0 InteractionObject -[creationNetDataForClient:]',
        selectors={
                 0x5f5bdc: (15198896, 'interactionObjectCreationNetData'),
                 0x5f5be4: (15198900, 'dataWithBytes:length:'),
        },
        imports={
                 0x5f5be0: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x5f5be8: (15245632, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(6249232, 'push {fp, lr}'), (6249452, 'adceq sb, r6, ip, asr 31')],
        calls=[(6249316, 'bl loc.imp.objc_msgSend_stret'), (6249352, 'bl sym.imp.memset'), (6249416, 'blx ip')],
        branches=[(6249300, 'beq', 6249324), (6249320, 'b', 6249356)],
        semantics=('[InteractionObject -[updateNetDataForClient:]] (imp 0x005f5b10, 56w): -[updateNetDataForClient:] (0x5f5b10, 56w): `return [NSData dataWithBytes:stret(self, interactionObjectCreationNetData) length:0x28]` - sret out of io_13 into a 0x28-byte buffer (nil-guard memset 0x28 when self==nil), wrapped in NSData (class OBJC_CLASS_$_NSData). Net transport of the creation blob; io_06 forwards its arg here..\n'),
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
        'batch': 'InteractionObject (E146): the interaction-object base; 33 bodies',
        'claim': ('the InteractionObject base (ownership protocol, net blob, defaults)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'interactionobject.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale interactionobject.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
