#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld giant draw composite (draw:...:hideUIType:): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 7203 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/DRAW_COMPOSITE.md for the prose and boundaries.
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
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
}

SPECS = [
    dict(
        name='wtl_draw_projectionmatrix_',
        method='DynamicWorld -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:]',
        types='v160@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152i156',
        start=9261040,
        end=9289852,
        disasm='disasm_worldtileloader_draw_projectionmatrix_modelviewmatrix_ca.txt',
        base_add=9261080,
        base_literal=9261680,
        boundary='ARM.exidx end 0x008dc07c (listing bound); next ObjC IMP 0x008dc07c DynamicWorld -[drawBlockheadBoxes:projectionMatrix:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x8d5278: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8d5280: (15216688, 'drawTransparentInventoryItem:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
                 0x8d71f0: (15216684, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
                 0x8d911c: (15216684, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
                 0x8db048: (15216684, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
                 0x8dc064: (15216684, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
        },
        imports={
                 0x8d5274: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8d527c: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8d6788: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8d6cb8: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8d71e8: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8d9650: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8dbae0: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8dc054: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9261040, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9261656, 'cmp r0, 3'), (9261744, 'ldr r4, [0x008d527c]'), (9262288, 'ldr r6, [0x008d5280]'), (9263096, 'ldr r4, [0x008d6788]'), (9264448, 'ldr r4, [0x008d6cb8]'), (9266404, 'ldr r4, [0x008d71f0]'), (9289820, 'invalid'), (9289848, 'rsbseq r4, r8, r8, lsl r8')],
        calls=[(9261804, 'bl sym.imp.memset'), (9261876, 'blx lr'), (9261984, 'bl sym.imp.objc_enumerationMutation'), (9262920, 'bl loc.imp.objc_msgSend'), (9263028, 'blx ip'), (9263156, 'bl sym.imp.memset'), (9263228, 'blx lr'), (9263336, 'bl sym.imp.objc_enumerationMutation'), (9264272, 'bl loc.imp.objc_msgSend'), (9264380, 'blx ip'), (9264508, 'bl sym.imp.memset'), (9264580, 'blx lr'), (9264688, 'bl sym.imp.objc_enumerationMutation'), (9265624, 'bl loc.imp.objc_msgSend'), (9265732, 'blx ip'), (9267020, 'bl loc.imp.objc_msgSend'), (9267064, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9268348, 'bl loc.imp.objc_msgSend'), (9268392, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9269676, 'bl loc.imp.objc_msgSend'), (9269720, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9271016, 'bl loc.imp.objc_msgSend'), (9271060, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9272344, 'bl loc.imp.objc_msgSend'), (9272388, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9273676, 'bl loc.imp.objc_msgSend'), (9273720, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9275000, 'bl loc.imp.objc_msgSend'), (9275044, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9276332, 'bl loc.imp.objc_msgSend'), (9276376, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9277660, 'bl loc.imp.objc_msgSend'), (9277704, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9278996, 'bl loc.imp.objc_msgSend'), (9279040, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9280328, 'bl loc.imp.objc_msgSend'), (9280372, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9281656, 'bl loc.imp.objc_msgSend'), (9281700, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9282984, 'bl loc.imp.objc_msgSend'), (9283028, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9284312, 'bl loc.imp.objc_msgSend'), (9284356, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9285640, 'bl loc.imp.objc_msgSend'), (9285684, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9286964, 'bl loc.imp.objc_msgSend'), (9287008, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9288336, 'bl loc.imp.objc_msgSend'), (9288376, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9289724, 'bl loc.imp.objc_msgSend'), (9289764, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9261672, 'beq', 9265764), (9261676, 'b', 9261704), (9261888, 'beq', 9263052), (9261976, 'beq', 9261988), (9262948, 'blo', 9261940), (9263048, 'bne', 9261940), (9263052, 'b', 9263056), (9263240, 'beq', 9264404), (9263328, 'beq', 9263340), (9264300, 'blo', 9263292), (9264400, 'bne', 9263292), (9264404, 'b', 9264408), (9264592, 'beq', 9265756), (9264680, 'beq', 9264692), (9265652, 'blo', 9264644), (9265752, 'bne', 9264644), (9265756, 'b', 9265760), (9265760, 'b', 9265764), (9266076, 'beq', 9267088), (9267076, 'b', 9265984), (9267404, 'beq', 9268416), (9268404, 'b', 9267308), (9268732, 'beq', 9269752), (9269732, 'b', 9268640), (9270072, 'beq', 9271084), (9271072, 'b', 9269976), (9271400, 'beq', 9272412), (9272400, 'b', 9271308), (9272732, 'beq', 9273744), (9273732, 'b', 9272636), (9274056, 'beq', 9275068), (9275056, 'b', 9273964), (9275388, 'beq', 9276400), (9276388, 'b', 9275292), (9276716, 'beq', 9277732), (9277716, 'b', 9276624), (9278052, 'beq', 9279068), (9279052, 'b', 9277956), (9279384, 'beq', 9280396), (9280384, 'b', 9279292), (9280712, 'beq', 9281724), (9281712, 'b', 9280620), (9282040, 'beq', 9283052), (9283040, 'b', 9281948), (9283368, 'beq', 9284380), (9284368, 'b', 9283276), (9284696, 'beq', 9285712), (9285696, 'b', 9284604), (9286020, 'beq', 9287032), (9287020, 'b', 9285928), (9287056, 'bge', 9288428), (9287396, 'beq', 9288392), (9288388, 'b', 9287304), (9288392, 'b', 9288396), (9288412, 'b', 9287044), (9288452, 'bge', 9289804), (9288784, 'beq', 9289780), (9289776, 'b', 9288692), (9289780, 'b', 9289784), (9289800, 'b', 9288440)],
        semantics=("draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType: is the world-line's top-level draw composite. Prologue 0x008d4ff0 (frame 0x470 + 0x2000 + 16-alignment = ~9.3 KB stack work area; base 0x105faf4; 7203 words).\nPhase gate: the hideUIType byte is read at [ip+0xde8] (`cmp r0, 3` @0x8d5258): `== 3` jumps straight to 0x8d6264 (the slice phases), otherwise the three collection phases run first.\nCollection phases (ffe2353c dispatch, 3 sites):\n  - **ffffe4f4 netBlockheads** enumerated @0x8d52b0; per element the **ffe2353c** call (@0x8d54d0) with the marshalled frame; loop guard @0x8d5374-0x8d5340 (`beq 0x8d57cc` exit).\n  - **ffffe4f0 local-client family** @0x8d57f8; ffe2353c again (@0x8d5a18); exit @0x8d5888 -> 0x8d5d14.\n  - **ffffe4f8 blockheads** @0x8d5d40; ffe2353c again (@0x8d5f60); exit @0x8d5dd0 -> 0x8d625c.\nSlice phases (ffe23538 dispatch, 18 sites): from 0x8d6264 onward the **ffffe54c member** (cell 0x8d71e8, 18 load sites) is walked slice by slice with `std::__1::__tree_next` iteration (@0x8d7c44 et al.); each slice's nodes dispatch through **ffe23538** (18 call sites, first @0x8d64e4, cells 0x8d71f0) with the camera bundle marshalled per element (the 6-word matrix copy walls, e.g. [r3+0xc]..[r3+0x88] -> [r0+0xc08]..[r0+0xc84]).\nTail tables: the **0x00E4AA3C** and **0x00E4AA0C** jump tables are read at the epilogue cells (@0x8dc05c / 0x8dc06c) - the 10-arm plant table and the 4-arm family table select the final arms.\nEnumerators: the NSFastEnumeration scaffold (ffe231ec) appears at 6 sites (@0x8d52a8 first), the containment/mutation guards with it.\nBoundary: this is a STRUCTURAL pass (frame, phases, dispatch cells, slice identity by member + tree iteration, tables) - a word-by-word transcription of all 7203 instructions is deliberately deferred; every claim above is anchored to the listing cells/members observed. The composite sits at the top of the draw call chain (E25/E41's drawInFrontOfBlocksObjects/drawOpaqueObjects/drawFreeBlocks are its parts).\n"),
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
        'batch': 'DynamicWorld giant draw composite (E44): draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld: cameraMinYWorld:cameraMaxYWorld:hideUIType:; 1 body, 7203 words, structural pass',
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
                        default=NATIVE / 'draw_composite.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale draw_composite.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
