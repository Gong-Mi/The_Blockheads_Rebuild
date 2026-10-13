#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the Workbench mid/smalls closure: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 786 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORKBENCH_SMALLS.md for the prose and boundaries.
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
    'bl 0xae2078': 0x00ae2078,
    'bl 0xae225c': 0x00ae225c,
    'bl 0xae2b64': 0x00ae2b64,
    'bl 0xae3538': 0x00ae3538,
    'bl 0xae3574': 0x00ae3574,
    'bl 0xafa8b0': 0x00afa8b0,
    'bl 0xafd54c': 0x00afd54c,
    'bl 0xb01800': 0x00b01800,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.__wrap_malloc': 0x001c2e58,
    'bl sym.imp.memset': 0x001c2924,
}

SPECS = [
    dict(
        name='ws_initlevel',
        method='Workbench -[initLevelStuff]',
        types='v8@0:4',
        start=11410124,
        end=11411576,
        disasm='disasm_worldtileloader_ws_initlevel.txt',
        base_add=11410140,
        base_literal=11411572,
        boundary='ARM.exidx end 0x00ae2078 (listing bound); next ObjC IMP 0x00ae3634 Workbench -[initSubDerivedItems]',
        selectors={
                 0xae2044: (15228648, 'expertMode'),
                 0xae2068: (15228656, 'customRules'),
                 0xae2070: (15228652, 'isCloudGame'),
        },
        imports={
                 0xae2040: (17151904, 'objc_msgSend'),
                 0xae2050: (17151968, '__stack_chk_guard'),
        },
        ivars={
                 0xae203c: (17165328, 'OBJC_IVAR_$_Workbench.craftableItems', 132),
                 0xae2048: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xae204c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xae2054: (17165336, 'OBJC_IVAR_$_Workbench.numberOfCraftableItemsUpToCurrentLevel', 128),
                 0xae2058: (17165340, 'OBJC_IVAR_$_Workbench.numberOfCraftableItems', 124),
                 0xae205c: (17165344, 'OBJC_IVAR_$_Workbench.requiresElectricity', 224),
                 0xae2060: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xae2064: (17165352, 'OBJC_IVAR_$_Workbench.requiresFuel', 221),
        },
        classes={},
        instructions=[(11410124, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11410252, 'blx r3'), (11410344, 'bl sym.imp.__wrap_malloc'), (11411572, 'subseq lr, r7, r0, lsl r0')],
        calls=[(11410252, 'blx r3'), (11410276, 'bl 0xae2078'), (11410344, 'bl sym.imp.__wrap_malloc'), (11410580, 'bl loc.imp.objc_msgSend'), (11410624, 'bl loc.imp.objc_msgSend'), (11410652, 'bl 0xae225c'), (11410752, 'bl loc.imp.objc_msgSend_stret'), (11410788, 'bl sym.imp.memset'), (11410872, 'blx r2'), (11411056, 'blx lr'), (11411112, 'blx r2'), (11411168, 'bl 0xae2b64'), (11411368, 'bl 0xae3538'), (11411448, 'bl 0xae3574'), (11411512, 'bl sym.imp.__stack_chk_fail')],
        branches=[(11410320, 'bne', 11410376), (11410452, 'bge', 11411312), (11410736, 'beq', 11410760), (11410756, 'b', 11410792), (11410808, 'bne', 11410900), (11411248, 'bgt', 11411292), (11411292, 'b', 11411296), (11411308, 'b', 11410440), (11411500, 'bne', 11411512)],
        semantics=("[Workbench initLevelStuff] (imp 0x00ae1acc, 363w): the level initializer - the type/position chain (fffff120 + ffffc8a0 + ffffbcec) calls the ffe263f4 helper (@0xae1b4c) then the per-level array: `movw r0, 2; lsl r1, r1, 2; __wrap_malloc` (@0xae1ba8: **malloc((level+1) << 2)** = the level-scaled 4-byte-entry array) stored through the **fffff11c cell** - the SAME pointer that dealloc's `__wrap_free` (E77) frees. Helper 0xae2078 for the derived state.\n"),
    ),
    dict(
        name='ws_title',
        method='Workbench -[title]',
        types='@8@0:4',
        start=11511784,
        end=11511984,
        disasm='disasm_worldtileloader_ws_title.txt',
        base_add=11511800,
        base_literal=11511980,
        boundary='ARM.exidx end 0x00afa8b0 (listing bound); next ObjC IMP 0x00afb128 Workbench -[craftableItems]',
        selectors={
                 0xafa89c: (15228648, 'expertMode'),
        },
        imports={
                 0xafa898: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xafa8a0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xafa8a4: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xafa8a8: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11511784, 'push {r4, r5, fp, lr}'), (11511948, 'bl 0xafa8b0'), (11511980, 'ldrsheq r5, [r6], -0x24')],
        calls=[(11511920, 'blx r3'), (11511948, 'bl 0xafa8b0')],
        branches=[],
        semantics=('[Workbench title] (imp 0x00afa7e8, 50w): the level-typed name lookup - the fffff130/f120 type chain + fffe263f4 helper + the derived-name helper 0xafa8b0 (the localized title per workbench level).\n'),
    ),
    dict(
        name='ws_reqphys',
        method='Workbench -[requiresPhysicalBlock]',
        types='c8@0:4',
        start=11527804,
        end=11528552,
        disasm='disasm_worldtileloader_ws_reqphys.txt',
        base_add=11527820,
        base_literal=11528548,
        boundary='ARM.exidx end 0x00afe968 (listing bound); next ObjC IMP 0x00afe968 Workbench -[setLevelSilently:]',
        selectors={
                 0xafe93c: (15229260, 'requiresPhysicalBlock'),
                 0xafe95c: (15229264, 'combinedLightForSolarPanelWithFullSunlight'),
        },
        imports={
                 0xafe938: (17151900, 'objc_msgSendSuper2'),
                 0xafe958: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xafe934: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xafe944: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xafe948: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xafe94c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xafe950: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xafe960: (17165464, 'OBJC_IVAR_$_Workbench.timeSinceFoundElectricty', 320),
        },
        classes={
                 0xafe940: (15253120, 'OBJC_CLASS_$_Workbench'),
        },
        instructions=[(11527804, 'push {fp, lr}'), (11527864, 'beq 0xafe724'), (11527948, 'movne r0, 1'), (11528548, 'subseq r1, r6, r0, ror 8')],
        calls=[(11528036, 'blx r3'), (11528288, 'blx r3')],
        branches=[(11527864, 'beq', 11527972), (11527908, 'bne', 11527956), (11527968, 'b', 11528488), (11528064, 'bne', 11528476), (11528108, 'bne', 11528476), (11528152, 'bne', 11528476), (11528188, 'bne', 11528320), (11528224, 'bge', 11528320), (11528316, 'bgt', 11528476), (11528360, 'bne', 11528468), (11528404, 'bge', 11528468)],
        semantics=('[Workbench requiresPhysicalBlock] (imp 0x00afe67c, 187w): the compound predicate - the **ffffcacc** gate (@0xafe6b8: set answers via the fffff160 byte, booleanized `movne 1; and; strb` @0xafe70c); else the super call (fffbca8 + ffe26658 @0xafe764) supplies the value.\n'),
    ),
    dict(
        name='ws_fbitem',
        method='Workbench -[freeblockCreationItemType]',
        types='i8@0:4',
        start=11523304,
        end=11523404,
        disasm='disasm_worldtileloader_ws_fbitem.txt',
        base_add=11523320,
        base_literal=11523400,
        boundary='ARM.exidx end 0x00afd54c (listing bound); next ObjC IMP 0x00afd7f0 Workbench -[freeBlockCreationSaveDict]',
        selectors={},
        imports={},
        ivars={
                 0xafd540: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xafd544: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11523304, 'push {fp, lr}'), (11523380, 'bl 0xafd54c'), (11523400, 'ldrsheq r2, [r6], -0x54')],
        calls=[(11523380, 'bl 0xafd54c')],
        branches=[],
        semantics=('[Workbench freeblockCreationItemType] (imp 0x00afd4e8, 25w): the type-keyed lookup through fffff130/f120 then the helper 0xafd54c (@0xafd534) - the item type offered when free-placing this workbench.\n'),
    ),
    dict(
        name='ws_fbsavedict',
        method='Workbench -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=11524080,
        end=11524156,
        disasm='disasm_worldtileloader_ws_fbsavedict.txt',
        base_add=11524096,
        base_literal=11524152,
        boundary='ARM.exidx end 0x00afd83c (listing bound); next ObjC IMP 0x00afd83c Workbench -[freeBlockCreationDataA]',
        selectors={
                 0xafd834: (15228888, 'getSaveDict'),
        },
        imports={
                 0xafd830: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11524080, 'push {fp, lr}'), (11524152, 'subseq r2, r6, ip, ror 5')],
        calls=[(11524132, 'blx r3')],
        branches=[],
        semantics=('[Workbench freeBlockCreationSaveDict] (imp 0x00afd7f0, 19w): forwarder via ffffbcac + ffe264e4.\n'),
    ),
    dict(
        name='ws_fbdataa',
        method='Workbench -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=11524156,
        end=11524212,
        disasm='disasm_worldtileloader_ws_fbdataa.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00afd874 (listing bound); next ObjC IMP 0x00afd858 Workbench -[freeBlockCreationDataB]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11524156, 'sub sp, sp, 8'), (11524208, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Workbench freeBlockCreationDataA] (imp 0x00afd83c, 14w): returns **0** (uxth) - the workbench places with dataA 0.\n'),
    ),
    dict(
        name='ws_fbdatab',
        method='Workbench -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=11524184,
        end=11524212,
        disasm='disasm_worldtileloader_ws_fbdatab.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00afd874 (listing bound); next ObjC IMP 0x00afd874 Workbench -[remove:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11524184, 'sub sp, sp, 8'), (11524208, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Workbench freeBlockCreationDataB] (imp 0x00afd858, 7w): returns **0**.\n'),
    ),
    dict(
        name='ws_objecttype',
        method='Workbench -[objectType]',
        types='i8@0:4',
        start=11410096,
        end=11410124,
        disasm='disasm_worldtileloader_ws_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ae1acc (listing bound); next ObjC IMP 0x00ae1acc Workbench -[initLevelStuff]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11410096, 'sub sp, sp, 8'), (11410120, 'bx lr')],
        calls=[],
        branches=[],
        semantics=("[Workbench objectType] (imp 0x00ae1ab0, 7w): returns **0x2d (45)** - the Workbench's dynamic-object type code (new pin for the type table).\n"),
    ),
    dict(
        name='ws_actiontitle',
        method='Workbench -[actionTitle]',
        types='@8@0:4',
        start=11540304,
        end=11540480,
        disasm='disasm_worldtileloader_ws_actiontitle.txt',
        base_add=11540320,
        base_literal=11540376,
        boundary='ARM.exidx end 0x00b01800 (listing bound); next ObjC IMP 0x00b0179c Workbench -[fuelItemCount]',
        selectors={
                 0xb01794: (15229292, 'title'),
        },
        imports={
                 0xb01790: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb017f4: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb017f8: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11540304, 'push {fp, lr}'), (11540476, 'subseq lr, r5, r0, asr 6')],
        calls=[(11540356, 'blx r3'), (11540456, 'bl 0xb01800')],
        branches=[],
        semantics=('[Workbench actionTitle] (imp 0x00b01750, 44w): forwarder via ffffbcac + **ffe26678** (the shared action-title target).\n'),
    ),
    dict(
        name='ws_titlecraft',
        method='Workbench -[titleForCraftProgressUI]',
        types='@8@0:4',
        start=11582348,
        end=11582628,
        disasm='disasm_worldtileloader_ws_titlecraft.txt',
        base_add=11582364,
        base_literal=11582420,
        boundary='ARM.exidx end 0x00b0bca4 (listing bound); next ObjC IMP 0x00b0bbd8 Workbench -[upgradeNameForCraftProgressUI]',
        selectors={
                 0xb0bbd0: (15229292, 'title'),
                 0xb0bc1c: (15229324, 'upgradeName'),
        },
        imports={
                 0xb0bbcc: (17151904, 'objc_msgSend'),
                 0xb0bc18: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11582348, 'push {fp, lr}'), (11582420, 'subseq r3, r5, r0, asr pc'), (11582624, 'pop {fp, pc}')],
        calls=[(11582400, 'blx r3'), (11582476, 'blx r3'), (11582552, 'bl sym.imp.__aeabi_idiv')],
        branches=[(11582584, 'bge', 11582600), (11582596, 'b', 11582608)],
        semantics=('[Workbench titleForCraftProgressUI] (imp 0x00b0bb8c, 70w; the listing region fuses the neighbor body at 0xb0bbd8): forwarders via ffffbcac + **ffe26678/ffe26698** - the crafting-progress UI title shares the action-title target family.\n'),
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
        'batch': 'Workbench mid/smalls closure (E79): initLevelStuff, title, requiresPhysicalBlock, the freeblock family and the titles; 10 bodies',
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
                        default=NATIVE / 'workbench_smalls.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale workbench_smalls.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
