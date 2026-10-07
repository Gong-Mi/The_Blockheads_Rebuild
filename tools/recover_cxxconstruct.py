#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld .cxx_construct member-constructor chain: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 866 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/CXX_CONSTRUCT.md for the prose and boundaries.
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
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__tree_std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true__const_': 0x00908080,
    'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__tree_std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true__const_': 0x00907fa0,
}

SPECS = [
    dict(
        name='wtl_cxx_construct',
        method='DynamicWorld -[.cxx_construct]',
        types='@8@0:4',
        start=9466392,
        end=9469856,
        disasm='disasm_dynamicworld_cxx_construct.txt',
        base_add=9466412,
        base_literal=9469852,
        boundary='ARM.exidx end 0x00907fa0 (listing bound); next ObjC IMP 0x00915d40 NavigateButtons -[initWithFrame:cache:windowInfo:]',
        selectors={},
        imports={},
        ivars={
                 0x907f4c: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x907f50: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x907f54: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x907f58: (17162360, 'OBJC_IVAR_$_DynamicWorld.currentlyAddingObjectIDs', 2432),
                 0x907f5c: (17162432, 'OBJC_IVAR_$_DynamicWorld.currentlyAddingGlowBlocks', 2412),
                 0x907f60: (17162364, 'OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition', 2400),
                 0x907f64: (17162388, 'OBJC_IVAR_$_DynamicWorld.currentlyLoadingMacroBlocks', 3732),
                 0x907f68: (17162368, 'OBJC_IVAR_$_DynamicWorld.partialUpdateOrderedObjects', 5032),
                 0x907f6c: (17162336, 'OBJC_IVAR_$_DynamicWorld.lightChangedSendUnreliablyMacroPositionsSingleClient', 6120),
                 0x907f70: (17162352, 'OBJC_IVAR_$_DynamicWorld.worldChangedDontSendMacroPositions', 6108),
                 0x907f74: (17162356, 'OBJC_IVAR_$_DynamicWorld.snowChangedMacroPositions', 6096),
                 0x907f78: (17162344, 'OBJC_IVAR_$_DynamicWorld.worldChangedSendUnreliablyMacroPositions', 6084),
                 0x907f7c: (17162412, 'OBJC_IVAR_$_DynamicWorld.worldChangedPositions', 6072),
                 0x907f80: (17162348, 'OBJC_IVAR_$_DynamicWorld.dynamicWorldChangedMacroPositions', 6540),
                 0x907f84: (17162448, 'OBJC_IVAR_$_DynamicWorld.worldPartialContentChangedPositions', 6528),
                 0x907f88: (17162424, 'OBJC_IVAR_$_DynamicWorld.worldContentsChangedPositions', 6516),
                 0x907f8c: (17162420, 'OBJC_IVAR_$_DynamicWorld.waterChangedPositions', 6504),
                 0x907f90: (17162428, 'OBJC_IVAR_$_DynamicWorld.avoidFreeblockDupeObjectIds', 9504),
                 0x907f94: (17162436, 'OBJC_IVAR_$_DynamicWorld.clientTreeLifeFraction', 9480),
                 0x907f98: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
        },
        classes={},
        instructions=[(9466392, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9466496, 'mov r0, r2'), (9466604, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__tree_std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true__const_'), (9466708, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__tree_std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true__const_'), (9466800, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__tree_std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true__const_'), (9466872, 'ldr r0, [0x00907f5c]'), (9468048, 'ldr r0, [0x00907f68]'), (9468912, 'ldr r0, [0x00907f80]'), (9469456, 'ldr r0, [0x00907f94]'), (9469608, 'bl method.Vector.Vector__'), (9469624, 'ldr ip, [0x00907f90]'), (9469764, 'sub sp, fp, 0x18'), (9469852, 'rsbseq r8, r5, r0, asr 17')],
        calls=[(9466500, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__tree_std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true__const_'), (9466604, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__tree_std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true__const_'), (9466708, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__tree_std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true__const_'), (9466800, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__tree_std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true__const_'), (9469608, 'bl method.Vector.Vector__')],
        branches=[(9466528, 'bne', 9466464), (9466632, 'bne', 9466568), (9466736, 'bne', 9466672), (9467624, 'bne', 9467248), (9468044, 'bne', 9467668), (9468212, 'bne', 9468084), (9468908, 'bne', 9468780), (9469452, 'bne', 9469324)],
        semantics=(".cxx_construct is the compiler-generated member-constructor chain of DynamicWorld (prologue 0x00907218, frame 0x5c0+; base 0x105faf4; 866 words; FULLY READ). Every C++ container member receives its constructor call in declaration order, and the numeric/flag members receive their scalar defaults (the constants vmov.f32 s0,1 = 1.0f; movw r4/r3,1; movw r7/r3,0). The container inventory:\n1. the three big map-array families: the __tree constructors run in 0x30c (65-segment) loops for the ffffe54c member (@0x907280; `add r2, r1, 0xc; cmp r2, r3; bne` iterating 12-byte segments), ffffe550 (@0x9072ec) and ffffe554 (@0x907354) - matching E29's destructor loops (0x30c/12 = 65);\n2. the ffffe588 map<u64, set<DynamicObject*>> __tree ctor (@0x9073b0) - the free-block registry member;\n3. the ffffe584 member region with the scalar defaults (@0x9073b8+; 1.0f stored via vstr, the 1/0 immediates) and the ffffe5cc member constructions (@0x9073f8+);\n4. the ffffe58c member's 0x30c loop (@0x907890+);\n5. the ffffe56c / ffffe57c / ffffe580 / ffffe574 / ffffe5b8 members (@0x907938-0x907ae8; each a vector/tree ctor with the 8-byte empty-head pattern `str ip,[r0]; str ip,[r0,4]; add r0,r0,8`);\n6. the ffffe578 member's 0x30c loop plus ffffe5dc / ffffe5c4 / ffffe5c0 (@0x907bf0+; ffffe5c0 carries the +0x180 slice marker seen in E23/E42);\n7. the ffffe5d0 member and the ffffe570 member vector (@0x907e10+);\n8. the final Vector member via **Vector::Vector()** (@0x907ea8) - the tail member;\n9. the ffffe5c8 member (the list family from E29's destructor) (@0x907eb8+).\nEpilogue 0x907f44 (`sub sp, fp, 0x18; pop {...}`). No external calls besides the STL constructors and Vector::Vector(); no branches besides the segment loops.\n"),
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
        'batch': 'DynamicWorld .cxx_construct member chain (E66): .cxx_construct; 1 body, 866 words, fully read',
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
                        default=NATIVE / 'cxx_construct.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale cxx_construct.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
