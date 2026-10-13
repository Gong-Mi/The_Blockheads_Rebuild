#!/usr/bin/env python3
"""Hash-gated recovery of the World ownership-signs line (E111).

The World ownership-signs line: the sign placement/sync writer pair,
the area overlay rebuild and the per-client lit-tile probe:
7 bodies, 1542 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_OWN.md for the prose and boundaries.
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
    'bl 0x55468c': 0x0055468c,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.macroPosForWorldPos_intpair__World_': 0x00a16594,
    'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_': 0x00a1770c,
}

SPECS = [
    dict(
        name='wo_00',
        method='World -[updateLocalOwnershipSignsDueToSignPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:]',
        types='v32@0:4{?=ii}8@16i20i24c28',
        start=6108620,
        end=6110728,
        disasm='disasm_worldtileloader_wo_00.txt',
        base_add=6108636,
        base_literal=6110724,
        boundary='ARM.exidx end 0x005d3e08 (listing bound); next ObjC IMP 0x005d3e08 World -[signOwnershipModificationRecievedFromServer:]',
        selectors={
                 0x5d3d9c: (15195892, 'init'),
                 0x5d3da0: (15195752, 'alloc'),
                 0x5d3da8: (15195624, 'objectForKey:'),
                 0x5d3db0: (15195708, 'stringWithFormat:'),
                 0x5d3dbc: (15195584, 'setObject:forKey:'),
                 0x5d3dc0: (15195688, 'array'),
                 0x5d3dc8: (15195604, 'count'),
                 0x5d3dd0: (15195572, 'numberWithInt:'),
                 0x5d3ddc: (15195684, 'dictionary'),
                 0x5d3dec: (15195700, 'addObject:'),
                 0x5d3df0: (15195736, 'removeObjectForKey:'),
                 0x5d3df4: (15197360, 'displayOwnershipAreas'),
                 0x5d3df8: (15195848, 'intValue'),
                 0x5d3dfc: (15195800, 'objectAtIndex:'),
                 0x5d3e00: (15196360, 'removeObjectAtIndex:'),
        },
        imports={
                 0x5d3d98: (17151904, 'objc_msgSend'),
                 0x5d3dac: (16232888, '__CFConstantStringClassReference'),
                 0x5d3dcc: (16233784, '__CFConstantStringClassReference'),
                 0x5d3dd8: (16233768, '__CFConstantStringClassReference'),
                 0x5d3de0: (16233800, '__CFConstantStringClassReference'),
                 0x5d3de4: (16233816, '__CFConstantStringClassReference'),
                 0x5d3de8: (16233832, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d3d94: (17155948, 'OBJC_IVAR_$_World.ownershipSignPositions', 3324),
                 0x5d3db8: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
        },
        classes={
                 0x5d3da4: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5d3db4: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5d3dc4: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
                 0x5d3dd4: (15245292, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(6108620, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6110724, 'adceq ip, r8, r0, lsl r5')],
        calls=[(6108808, 'blx r2'), (6108824, 'blx r2'), (6108880, 'bl sym.macroPosForWorldPos_intpair__World_'), (6109040, 'blx r4'), (6109084, 'blx ip'), (6109200, 'blx lr'), (6109248, 'blx lr'), (6109312, 'blx r2'), (6109428, 'blx r5'), (6109456, 'blx r3'), (6109472, 'blx r2'), (6109560, 'blx ip'), (6109576, 'blx r2'), (6109648, 'blx r3'), (6109828, 'blx r3'), (6109876, 'blx r3'), (6109912, 'blx ip'), (6109956, 'blx r3'), (6109992, 'blx ip'), (6110076, 'blx ip'), (6110188, 'blx lr'), (6110224, 'blx ip'), (6110336, 'blx lr'), (6110372, 'blx ip'), (6110424, 'blx r3'), (6110472, 'blx r2'), (6110552, 'blx r3'), (6110600, 'blx r2')],
        branches=[(6108724, 'bne', 6108848), (6108736, 'bne', 6108848), (6109104, 'bne', 6109252), (6109116, 'bne', 6109252), (6109324, 'bhs', 6109688), (6109484, 'bne', 6109668), (6109588, 'bne', 6109668), (6109668, 'b', 6109672), (6109684, 'b', 6109264), (6109696, 'bne', 6110432), (6110008, 'beq', 6110080), (6110088, 'beq', 6110228), (6110236, 'beq', 6110376), (6110428, 'b', 6110560), (6110480, 'bne', 6110556), (6110556, 'b', 6110560)],
        semantics=('[World updateLocalOwnershipSignsDueToSignPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:] (imp 0x005d35cc, 527w): the ownership-map writer - resolves the macro pos (macroPosForWorldPos), then reads/writes the ownershipSignPositions dictionary per affected cell (objectForKey:/setObject:forKey: with numberWithInt: keys and stringWithFormat: owner strings), maintains the per-cell NSMutableArray lists (addObject:/removeObjectForKey:/removeObjectAtIndex:) and refreshes displayOwnershipAreas.\n'),
    ),
    dict(
        name='wo_01',
        method='World -[ownershipSignWasPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:]',
        types='v32@0:4{?=ii}8@16i20i24c28',
        start=6111556,
        end=6113048,
        disasm='disasm_worldtileloader_wo_01.txt',
        base_add=6111572,
        base_literal=6113044,
        boundary='ARM.exidx end 0x005d4718 (listing bound); next ObjC IMP 0x005d4718 World -[tileIsProtectedAtPos:againstClient:]',
        selectors={
                 0x5d46bc: (15198328, 'updateLocalOwnershipSignsDueToSignPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:'),
                 0x5d46d0: (15195584, 'setObject:forKey:'),
                 0x5d46d4: (15195572, 'numberWithInt:'),
                 0x5d46e0: (15195684, 'dictionary'),
                 0x5d46f0: (15195576, 'numberWithBool:'),
                 0x5d46fc: (15195640, 'sendNetworkData:toPeers:reliable:'),
                 0x5d4700: (15195612, 'appendData:'),
                 0x5d4704: (15195608, 'gzipDeflate'),
                 0x5d4708: (15195552, 'dataWithBytes:length:'),
        },
        imports={
                 0x5d46c8: (16233784, '__CFConstantStringClassReference'),
                 0x5d46cc: (17151904, 'objc_msgSend'),
                 0x5d46dc: (16233768, '__CFConstantStringClassReference'),
                 0x5d46e8: (16233800, '__CFConstantStringClassReference'),
                 0x5d46ec: (16233848, '__CFConstantStringClassReference'),
                 0x5d46f4: (16233816, '__CFConstantStringClassReference'),
                 0x5d46f8: (16233832, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d46b8: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d46c4: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5d4710: (17156052, 'OBJC_IVAR_$_World.ownershipSignPositionsNeedSaving', 3328),
        },
        classes={
                 0x5d46d8: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5d46e4: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5d470c: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6111556, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6113044, 'umlaleq fp, r8, r8, sb')],
        calls=[(6111744, 'bl loc.imp.objc_msgSend'), (6111948, 'blx r3'), (6111996, 'blx r3'), (6112032, 'blx ip'), (6112076, 'blx r3'), (6112112, 'blx ip'), (6112196, 'blx ip'), (6112312, 'blx lr'), (6112348, 'blx ip'), (6112460, 'blx lr'), (6112496, 'blx ip'), (6112608, 'blx lr'), (6112644, 'blx ip'), (6112712, 'blx ip'), (6112724, 'bl 0x55468c'), (6112824, 'blx r2'), (6112852, 'blx r3'), (6112908, 'blx lr')],
        branches=[(6111776, 'bne', 6112944), (6111816, 'beq', 6112912), (6112128, 'beq', 6112200), (6112208, 'beq', 6112352), (6112360, 'beq', 6112500), (6112508, 'beq', 6112648)],
        semantics=('[World ownershipSignWasPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:] (imp 0x005d4144, 373w): the sign-event entry - applies updateLocalOwnershipSignsDueToSignPlacedOrChangedAtPos:... locally, then builds the net packet (dictionary + numberWithInt:/numberWithBool:, gzipDeflate, dataWithBytes:length:) and relays via sendNetworkData:toPeers:reliable:; ownershipSignPositionsNeedSaving flag; helper 0x55468c (fifth appearance); constant 0x3d (61).\n'),
    ),
    dict(
        name='wo_02',
        method='World -[signOwnershipModificationRecievedFromServer:]',
        types='v12@0:4@8',
        start=6110728,
        end=6111556,
        disasm='disasm_worldtileloader_wo_02.txt',
        base_add=6110744,
        base_literal=6111552,
        boundary='ARM.exidx end 0x005d4144 (listing bound); next ObjC IMP 0x005d4144 World -[ownershipSignWasPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:]',
        selectors={
                 0x5d4118: (15195624, 'objectForKey:'),
                 0x5d411c: (15195828, 'boolValue'),
                 0x5d4128: (15195848, 'intValue'),
                 0x5d4138: (15198328, 'updateLocalOwnershipSignsDueToSignPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:'),
        },
        imports={
                 0x5d4110: (16233816, '__CFConstantStringClassReference'),
                 0x5d4114: (17151904, 'objc_msgSend'),
                 0x5d4120: (16233848, '__CFConstantStringClassReference'),
                 0x5d4124: (16233800, '__CFConstantStringClassReference'),
                 0x5d412c: (16233784, '__CFConstantStringClassReference'),
                 0x5d4130: (16233768, '__CFConstantStringClassReference'),
                 0x5d4134: (16233832, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(6110728, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6111552, 'invalid')],
        calls=[(6110932, 'blx r5'), (6110948, 'blx r2'), (6110976, 'blx r3'), (6110992, 'blx r2'), (6111020, 'blx r3'), (6111048, 'blx r3'), (6111064, 'blx r2'), (6111112, 'blx r3'), (6111200, 'blx ip'), (6111216, 'blx r2'), (6111284, 'blx r3'), (6111372, 'blx ip'), (6111388, 'blx r2'), (6111492, 'bl loc.imp.objc_msgSend')],
        branches=[(6111124, 'beq', 6111224), (6111296, 'beq', 6111396)],
        semantics=('[World signOwnershipModificationRecievedFromServer:] (imp 0x005d3e08, 207w): the server-side modification intake - objectForKey:/boolValue/intValue decode then updateLocalOwnershipSignsDueToSignPlacedOrChangedAtPos:...; constant 0xf.\n'),
    ),
    dict(
        name='wo_03',
        method='World -[displayOwnershipAreas]',
        types='v8@0:4',
        start=6116272,
        end=6116660,
        disasm='disasm_worldtileloader_wo_03.txt',
        base_add=6116288,
        base_literal=6116656,
        boundary='ARM.exidx end 0x005d5534 (listing bound); next ObjC IMP 0x005d5534 World -[renderingTeaserFrames]',
        selectors={
                 0x5d5510: (15195604, 'count'),
                 0x5d551c: (15196056, 'initWithWorld:cache:'),
                 0x5d5524: (15195752, 'alloc'),
                 0x5d552c: (15197360, 'displayOwnershipAreas'),
        },
        imports={
                 0x5d550c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d5514: (17155948, 'OBJC_IVAR_$_World.ownershipSignPositions', 3324),
                 0x5d5518: (17156372, 'OBJC_IVAR_$_World.ownershipAreaRenderer', 3332),
                 0x5d5520: (17156132, 'OBJC_IVAR_$_World.cache', 408),
        },
        classes={
                 0x5d5528: (15245540, 'OBJC_CLASS_$_OwnershipAreaRenderer'),
        },
        instructions=[(6116272, 'push {r4, r5, fp, lr}'), (6116656, 'adceq sl, r8, ip, lsr 14')],
        calls=[(6116348, 'blx r3'), (6116484, 'blx r2'), (6116524, 'blx ip'), (6116608, 'blx r2')],
        branches=[(6116356, 'bls', 6116612), (6116396, 'bne', 6116548)],
        semantics=('[World displayOwnershipAreas] (imp 0x005d53b0, 97w): rebuilds the ownership-area overlay - OwnershipAreaRenderer initWithWorld:cache: gated on the ownershipSignPositions count; ownershipAreaRenderer slot.\n'),
    ),
    dict(
        name='wo_04',
        method='World -[signOwnershipPlayerListRecievedFromServer:]',
        types='v12@0:4@8',
        start=6108472,
        end=6108620,
        disasm='disasm_worldtileloader_wo_04.txt',
        base_add=6108488,
        base_literal=6108616,
        boundary='ARM.exidx end 0x005d35cc (listing bound); next ObjC IMP 0x005d35cc World -[updateLocalOwnershipSignsDueToSignPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:]',
        selectors={
                 0x5d35bc: (15198324, 'signOwnershipPlayerListRecievedFromServer:'),
                 0x5d35c0: (15198320, 'ownershipSignUI'),
        },
        imports={
                 0x5d35b8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d35c4: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6108472, 'push {r4, r5, r6, sl, fp, lr}'), (6108616, 'adceq ip, r8, r4, lsr 11')],
        calls=[(6108568, 'blx ip'), (6108588, 'blx r3')],
        branches=[],
        semantics=('[World signOwnershipPlayerListRecievedFromServer:] (imp 0x005d3538, 37w): forwards the player list to uiManager signOwnershipUI.\n'),
    ),
    dict(
        name='wo_05',
        method='World -[ownershipSignUIDisplayed]',
        types='c8@0:4',
        start=6138388,
        end=6138448,
        disasm='disasm_worldtileloader_wo_05.txt',
        base_add=6138396,
        base_literal=6138444,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005daa50 World -[workbenchProgressBarUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6138388, 'sub sp, sp, 8'), (6138444, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World ownershipSignUIDisplayed] (imp 0x005daa14, 15w): bare getter (listing trimmed at the next IMP).\n'),
    ),
    dict(
        name='wo_06',
        method='World -[tileIsLitForClient:atPos:tile:]',
        types='c24@0:4@8{?=ii}12^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}20',
        start=6064304,
        end=6065448,
        disasm='disasm_worldtileloader_wo_06.txt',
        base_add=6064320,
        base_literal=6065444,
        boundary='ARM.exidx end 0x005c8d28 (listing bound); next ObjC IMP 0x005c8d28 World -[mapVisible]',
        selectors={
                 0x5c8cf8: (15196544, 'lightBlockIndex'),
                 0x5c8cfc: (15195624, 'objectForKey:'),
                 0x5c8d08: (15198060, 'loadLightBlockForClientLightBlockIndex:intoPhysicalBlock:'),
                 0x5c8d10: (15195988, 'worldWidthMacro'),
        },
        imports={
                 0x5c8cf4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c8cf0: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5c8d00: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x5c8d04: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={},
        instructions=[(6064304, 'push {r4, r5, r6, sl, fp, lr}'), (6065444, 'adceq r7, sb, ip, lsr 4')],
        calls=[(6064552, 'blx ip'), (6064568, 'blx r2'), (6064640, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (6064816, 'bl loc.imp.objc_msgSend'), (6064928, 'bl loc.imp.objc_msgSend'), (6064952, 'bl sym.imp.__aeabi_idiv'), (6065024, 'bl loc.imp.objc_msgSend'), (6065120, 'bl loc.imp.objc_msgSend'), (6065136, 'bl sym.imp.__aeabi_idiv'), (6065208, 'bl loc.imp.objc_msgSend')],
        branches=[(6064392, 'beq', 6064412), (6064408, 'bne', 6064464), (6064424, 'beq', 6064460), (6064456, 'b', 6065380), (6064460, 'b', 6064464), (6064584, 'blt', 6065372), (6064660, 'beq', 6065368), (6064680, 'beq', 6065368), (6064700, 'beq', 6065368), (6064768, 'bne', 6064844), (6064856, 'beq', 6065364), (6064964, 'blt', 6065056), (6065052, 'b', 6065280), (6065148, 'bge', 6065240), (6065236, 'b', 6065272), (6065360, 'b', 6065380), (6065364, 'b', 6065368), (6065368, 'b', 6065372)],
        semantics=('[World tileIsLitForClient:atPos:tile:] (imp 0x005c88b0, 286w): the per-client light-visibility probe - macroTileAtWorldPostion + lightBlockIndex + loadLightBlockForClientLightBlockIndex:intoPhysicalBlock: (the light-block sync loader pair), worldWidthMacro wrap with __aeabi_idiv x2; server/serverClients/macroTiles.\n'),
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
        'batch': 'World ownership-signs line (E111): the sign placement/sync pair, the area overlay and the lit-for-client probe; 7 bodies',
        'claim': ('a fully-read static map of the World ownership-signs line; the OwnershipAreaRenderer and uiManager contracts are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_own.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_own.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
