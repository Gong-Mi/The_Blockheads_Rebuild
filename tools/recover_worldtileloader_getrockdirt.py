#!/usr/bin/env python3
"""Byte-gated map for WorldTileLoader -[getRockAndDirtHeightforX:rockHeight:dirtHeight:]."""
import argparse
import hashlib
import io
import json
import re
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
START, END = 0x00857188, 0x00857340
BASE = 0x0105FAF4
BASE_ADD, BASE_LITERAL = 0x00857220, 0x00857320
MSGSEND_STUB, MSGSEND_GOT = 0x001C281C, 0x0105B7A0

# literal cell -> GOT slot -> reviewed selector/ivar
CELLS = {
    0x0085731C: (0x0105DD4C, 'OBJC_IVAR_$_WorldTileLoader.world', 'ivar', 4),
    0x00857324: (0x00E823A8, 'worldWidthMacro', 'selector', None),
    0x00857330: (0x0105DD60, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 'ivar', 96),
    0x00857338: (0x0105DD5C, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 'ivar', 92),
}
CALLS = (0x008571EC, 0x00857248, 0x00857298)
BRANCHES = (
    (0x008571B4, 0x0085720C),
    (0x00857208, 0x008572B8),
    (0x00857260, 0x008572B4),
    (0x008572B4, 0x008572B8),
)


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site, word):
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl: {word:#x}')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xFFFFFFFF


def b_target(site, word):
    if (word >> 25) & 7 != 5:
        raise ValueError(f'{site:#x} is not ARM b: {word:#x}')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xFFFFFFFF


def cstr(memory, address):
    off = memory.offset(address, 1)
    if off is None:
        return None
    end = memory.data.find(b'\0', off, off + 256)
    return memory.data[off:end].decode('utf-8', 'replace') if end >= 0 else None


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_worldtileloader_getrockdirt.txt').read_text()
    words = verify_disassembly(memory, text, START, END)
    base = (BASE_ADD + 8 + signed(memory.word(BASE_LITERAL))) & 0xFFFFFFFF
    if base != BASE:
        raise ValueError(f'PIC base drift: {base:#x}')
    if memory.imports.get(MSGSEND_GOT) != 'objc_msgSend':
        raise ValueError('objc_msgSend GOT slot drifted')

    elf = ELFFile(io.BytesIO(path.read_bytes()))
    symbols = {s['st_value']: s.name for s in elf.get_section_by_name('.dynsym').iter_symbols()}
    resolved = {}
    for cell, (slot_expected, name, kind, offset_expected) in CELLS.items():
        slot = (base + signed(memory.word(cell))) & 0xFFFFFFFF
        if slot != slot_expected:
            raise ValueError(f'cell {cell:#x} -> {slot:#x}, expected {slot_expected:#x}')
        value = memory.word(slot)
        if kind == 'selector':
            if cstr(memory, value) != name:
                raise ValueError(f'selector drift at {cell:#x}: {cstr(memory, value)!r}')
        else:
            if symbols.get(value) != name:
                raise ValueError(f'ivar drift at {cell:#x}: {symbols.get(value)!r}')
            if memory.word(value) != offset_expected:
                raise ValueError(f'ivar offset drift for {name}')
        resolved[f'0x{cell:08x}'] = {
            'slot': f'0x{slot:08x}', 'kind': kind, 'name': name,
            **({'offset': offset_expected} if offset_expected is not None else {}),
        }

    rows = {}
    for line in text.splitlines():
        match = re.search(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', line)
        if match:
            rows[int(match[1], 16)] = match[2].strip().replace('#', '')
    listed_calls = {a for a, instruction in rows.items()
                    if re.match(r'^bl\s', instruction) and a in rows}
    if listed_calls != set(CALLS):
        raise ValueError(f'call set drifted: {sorted(listed_calls ^ set(CALLS))}')
    for site in CALLS:
        if bl_target(site, memory.word(site)) != MSGSEND_STUB:
            raise ValueError(f'{site:#x} no longer targets objc_msgSend PLT')
    for site, destination in BRANCHES:
        if b_target(site, memory.word(site)) != destination:
            raise ValueError(f'branch {site:#x} drifted')

    return {
        'method': 'WorldTileLoader -[getRockAndDirtHeightforX:rockHeight:dirtHeight:]',
        'types': 'v20@0:4i8^i12^i16',
        'elf_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'imp': f'0x{START:08x}',
        'arm_exidx_end': f'0x{END:08x}',
        'verified_words': words,
        'pic_base': f'0x{base:08x}',
        'msgsend_stub': f'0x{MSGSEND_STUB:08x}',
        'msgsend_got_slot': f'0x{MSGSEND_GOT:08x}',
        'cells': resolved,
        'calls': [f'0x{x:08x}' for x in CALLS],
        'branches': [{'address': f'0x{a:08x}', 'destination': f'0x{d:08x}'}
                     for a, d in BRANCHES],
        'decision': (
            'x is wrapped once into [0, worldWidthMacro*32): if x < 0, '
            'x += worldWidthMacro*32; else if x >= worldWidthMacro*32, '
            'x -= worldWidthMacro*32. The method then writes '
            '*rockHeight = self->rockHeights[x] and *dirtHeight = '
            'self->dirtHeights[x]. worldWidthMacro is queried through '
            '[self->world worldWidthMacro] in each wrap path; three objc_msgSend '
            'sites are byte-anchored to the shared PLT.'),
        'claim': 'static bounded-body map; no runtime array contents or caller timing proof',
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldtileloader_getrockdirt.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldtileloader_getrockdirt.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} calls={len(report['calls'])} branches={len(report['branches'])} cells={len(report['cells'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
