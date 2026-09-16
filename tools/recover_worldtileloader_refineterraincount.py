#!/usr/bin/env python3
"""Byte-gated, hand-reviewed WorldTileLoader -[refineTerrainCount] evidence map.

IMP 0x00854c18 .. ARM.exidx end 0x00854c54 (15 words including literal pool),
PIC/GOT base 0x0105faf4 (same GOT as the GameView compilation-unit family).
The checked-in listing is re-verified word-by-word against the SHA-256-pinned
ELF; the ivar literal below is anchored to a verified address and the tool
refuses to emit on any drift.

Reviewed semantics: this is a pure ivar getter. It loads
OBJC_IVAR_$_WorldTileLoader.refineTerrainCount (offset 232) and returns the
stored int. No calls, no branches. The count is presumably consumed by
-[refineTerrain] (IMP 0x00854c54), which is outside this body.

Static bounded-body map only: NOT a proof of who writes the ivar or when.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
START, END = 0x00854C18, 0x00854C54
EXPECTED_BASE = 0x0105FAF4
BASE_ADD = 0x00854C20
BASE_LITERAL = 0x00854C50
IVAR_CELL = 0x00854C4C
EXPECTED_IVAR_SLOT = 0x0105DDBC


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_worldtileloader_refineterraincount.txt').read_text()
    words = verify_disassembly(memory, text, START, END)

    base = (BASE_ADD + 8 + signed(memory.word(BASE_LITERAL))) & 0xffffffff
    if base != EXPECTED_BASE:
        raise ValueError(f'PIC base drift {base:#x}')

    slot = (base + signed(memory.word(IVAR_CELL))) & 0xffffffff
    if slot != EXPECTED_IVAR_SLOT:
        raise ValueError(f'ivar cell resolved to {slot:#x}, expected {EXPECTED_IVAR_SLOT:#x}')
    entry = memory.word(slot)
    elf = ELFFile(io.BytesIO(path.read_bytes()))
    symbols = {s['st_value']: s.name
               for s in elf.get_section_by_name('.dynsym').iter_symbols()}
    symbol = symbols.get(entry, '')
    if symbol != 'OBJC_IVAR_$_WorldTileLoader.refineTerrainCount':
        raise ValueError(f'ivar cell drifted: {symbol}')

    # No bl/blx in the body; the only transfer is the terminating bx lr.
    for addr in range(START, 0x00854C4C, 4):
        word = memory.word(addr)
        if word >> 24 in (0xEB, 0xFA) or (word & 0x0F000000) == 0x0B000000:
            raise ValueError(f'unexpected call/branch encoding at {addr:#x}')

    return {
        'method': 'WorldTileLoader -[refineTerrainCount]',
        'types': 'i8@0:4',
        'elf_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'imp': f'0x{START:08x}',
        'arm_exidx_end': f'0x{END:08x}',
        'verified_words': words,
        'pic_base': f'0x{base:08x}',
        'ivar': {'cell': f'0x{IVAR_CELL:08x}', 'slot': f'0x{slot:08x}',
                 'symbol': symbol, 'offset': memory.word(entry)},
        'decision': ('pure ivar getter: returns *(int*)(self + 232), the '
                     'refineTerrainCount field. No calls, no branches.'),
        'claim': ('static bounded-body map; writer identity and write '
                  'timing of the ivar are outside this body'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldtileloader_refineterraincount.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldtileloader_refineterraincount.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} ivar={report['ivar']['symbol']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
