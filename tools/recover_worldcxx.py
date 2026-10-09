#!/usr/bin/env python3
"""Hash-gated recovery of the World internals pair (E113).

The World internals pair: the compiler-generated C++ member constructor
(the member-layout oracle) and the physical-block streaming loader:
2 bodies, 1346 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_CXX.md for the prose and boundaries.
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
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.Vector2.Vector2__': 0x004d5170,
    'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_': 0x005dd340,
    'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.erase_std::__1::__hash_const_iterator_std::__1::__hash_node_PhysicalBlock__void__const__': 0x005dbdcc,
    'bl method.std::__1::__tree_std::__1::pair_int__unsigned_char___std::__1::__map_value_compare_int__unsigned_char__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__unsigned_char_____.__tree_std::__1::__map_value_compare_int__unsigned_char__std::__1::less_int___true__const_': 0x005db074,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.__wrap_calloc': 0x001c2fe4,
    'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_': 0x00a16ccc,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
}

SPECS = [
    dict(
        name='wc_00',
        method='World -[.cxx_construct]',
        types='@8@0:4',
        start=6138724,
        end=6140020,
        disasm='disasm_worldtileloader_wc_00.txt',
        base_add=6138740,
        base_literal=6140016,
        boundary='ARM.exidx end 0x005db074 (listing bound); next ObjC IMP 0x005e48f8 TradingPost -[objectType]',
        selectors={},
        imports={},
        ivars={
                 0x5db040: (17156756, 'OBJC_IVAR_$_World.lastDistanceTravelledThisDPadMovement', 3364),
                 0x5db044: (17155864, 'OBJC_IVAR_$_World.lastPinchPanTranslation', 3356),
                 0x5db048: (17155868, 'OBJC_IVAR_$_World.touchStartTranslation', 3348),
                 0x5db04c: (17156624, 'OBJC_IVAR_$_World.latestMapData', 3192),
                 0x5db050: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x5db054: (17156524, 'OBJC_IVAR_$_World.sunDirection', 660),
                 0x5db058: (17155884, 'OBJC_IVAR_$_World.translationGoal', 632),
                 0x5db05c: (17155860, 'OBJC_IVAR_$_World.accurateTranslation', 624),
                 0x5db060: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x5db064: (17156368, 'OBJC_IVAR_$_World.freePhysicalBlocks', 476),
                 0x5db068: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
                 0x5db06c: (17156680, 'OBJC_IVAR_$_World.longTermAveragedAcceleration', 28),
        },
        classes={},
        instructions=[(6138724, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6140016, 'adceq r4, r8, r8, ror pc')],
        calls=[(6138776, 'bl method.Vector.Vector__'), (6139632, 'bl method.Vector2.Vector2__'), (6139668, 'bl method.Vector2.Vector2__'), (6139704, 'bl method.Vector2.Vector2__'), (6139740, 'bl method.Vector.Vector__'), (6139776, 'bl method.Vector.Vector__'), (6139836, 'bl method.std::__1::__tree_std::__1::pair_int__unsigned_char___std::__1::__map_value_compare_int__unsigned_char__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__unsigned_char_____.__tree_std::__1::__map_value_compare_int__unsigned_char__std::__1::less_int___true__const_'), (6139872, 'bl method.Vector2.Vector2__'), (6139908, 'bl method.Vector2.Vector2__'), (6139944, 'bl method.Vector2.Vector2__')],
        branches=[],
        semantics=('[World .cxx_construct] (imp 0x005dab64, 324w): the compiler-generated C++ member constructor - Vector2::Vector2() x6 + Vector::Vector() x3 + one std::__1::__tree<int, unsigned char> (std::map<int, uint8>) ctor; the ivar-offset slots touched are lastDistanceTravelledThisDPadMovement / lastPinchPanTranslation / touchStartTranslation / latestMapData / dayColor / sunDirection / translationGoal / accurateTranslation / roundedTranslation / freePhysicalBlocks / usedPhysicalBlocks / longTermAveragedAcceleration - the census-grade map of what the generated ctor initializes (the World C++ member-layout oracle).\n'),
    ),
    dict(
        name='wc_01',
        method='World -[loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:]',
        types='v28@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8i12i16c20c24',
        start=5982720,
        end=5986808,
        disasm='disasm_worldtileloader_wc_01.txt',
        base_add=5982736,
        base_literal=5986804,
        boundary='ARM.exidx end 0x005b59f8 (listing bound); next ObjC IMP 0x005b59f8 World -[setWindowInfo:]',
        selectors={
                 0x5b59bc: (15197524, 'raise:format:'),
                 0x5b59d0: (15197528, 'loadPhysicalBlock:atXPos:yPos:createIfNotCreated:'),
                 0x5b59d4: (15197532, 'addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:'),
                 0x5b59dc: (15195844, 'timeIntervalSinceReferenceDate'),
                 0x5b59e8: (15196508, 'loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:'),
                 0x5b59f0: (15197520, 'requestBlockFromServerAtPos:createIfNotCreated:'),
        },
        imports={
                 0x5b59b0: (16232472, '__CFConstantStringClassReference'),
                 0x5b59b4: (16232488, '__CFConstantStringClassReference'),
                 0x5b59b8: (17151904, 'objc_msgSend'),
                 0x5b59c4: (16232456, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5b59a0: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
                 0x5b59a4: (17156368, 'OBJC_IVAR_$_World.freePhysicalBlocks', 476),
                 0x5b59ac: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
                 0x5b59c8: (17168140, 'OBJC_IVAR_$_ServerClient.timeSinceLastHeartbeatRequest', 60),
                 0x5b59cc: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x5b59d8: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5b59e4: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={
                 0x5b59c0: (15245484, 'OBJC_CLASS_$_NSException'),
                 0x5b59e0: (15245312, 'OBJC_CLASS_$_NSDate'),
        },
        instructions=[(5982720, 'push {r4, r5, r6, sl, fp, lr}'), (5986804, 'invalid')],
        calls=[(5982936, 'bl sym.makeIntpair_int__int_'), (5982980, 'bl loc.imp.objc_msgSend'), (5983096, 'bl sym.imp.__wrap_calloc'), (5983132, 'bl sym.imp.NSLog'), (5983224, 'blx r4'), (5983252, 'bl sym.imp.__wrap_calloc'), (5983312, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_'), (5983612, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_'), (5983744, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.erase_std::__1::__hash_const_iterator_std::__1::__hash_node_PhysicalBlock__void__const__'), (5983932, 'blx ip'), (5984028, 'blx ip'), (5984084, 'blx r2'), (5984212, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5984328, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5984444, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5984560, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5984680, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5984800, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5984920, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5985040, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5985200, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5985320, 'blx lr'), (5985396, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5985516, 'blx lr'), (5985596, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5985716, 'blx lr'), (5985792, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5985912, 'blx lr'), (5985988, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5986108, 'blx lr'), (5986188, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5986308, 'blx lr'), (5986384, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5986504, 'blx lr'), (5986584, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5986704, 'blx lr')],
        branches=[(5982800, 'beq', 5982820), (5982816, 'beq', 5985108), (5982856, 'beq', 5982988), (5982876, 'bne', 5982988), (5982984, 'b', 5986712), (5983012, 'bne', 5983796), (5983084, 'bne', 5983412), (5983116, 'bne', 5983232), (5983228, 'b', 5986712), (5983408, 'b', 5983792), (5983792, 'b', 5983796), (5983832, 'beq', 5984036), (5983948, 'beq', 5984032), (5984032, 'b', 5984036), (5984116, 'beq', 5985104), (5984136, 'beq', 5984156), (5984232, 'beq', 5984272), (5984252, 'beq', 5984272), (5984348, 'beq', 5984388), (5984368, 'beq', 5984388), (5984464, 'beq', 5984504), (5984484, 'beq', 5984504), (5984580, 'beq', 5984620), (5984600, 'beq', 5984620), (5984700, 'beq', 5984740), (5984720, 'beq', 5984740), (5984820, 'beq', 5984860), (5984840, 'beq', 5984860), (5984940, 'beq', 5984980), (5984960, 'beq', 5984980), (5985060, 'beq', 5985100), (5985080, 'beq', 5985100), (5985100, 'b', 5985104), (5985104, 'b', 5985112), (5985108, 'b', 5985112), (5985120, 'beq', 5986712), (5985220, 'beq', 5985324), (5985416, 'beq', 5985520), (5985616, 'beq', 5985720), (5985812, 'beq', 5985916), (5986008, 'beq', 5986112), (5986208, 'beq', 5986312), (5986404, 'beq', 5986508), (5986604, 'beq', 5986708), (5986708, 'b', 5986712)],
        semantics=('[World loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:] (imp 0x005b4a00, 1022w): the physical-block streaming loader - macroTileAtMacroPostion x16 over the surrounding macro tiles, per-block loadPhysicalBlock:atXPos:yPos:createIfNotCreated:, light bookkeeping via addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:, the client-side miss path requestBlockFromServerAtPos:createIfNotCreated: (clientTileLoader), free/usedPhysicalBlocks hash-table insert x2 + erase via __wrap_calloc x2, makeIntpair; constants 0xc0/0x400/0x40; NSException raise:format: error path + NSLog; 45 branches.\n'),
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
        'batch': 'World internals pair (E113): the C++ member constructor and the physical-block streaming loader; 2 bodies',
        'claim': ('a fully-read static map of the World C++ member constructor and the physical-block streaming loader; the std::container internals and the clientTileLoader request path timing are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_cxx.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_cxx.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
