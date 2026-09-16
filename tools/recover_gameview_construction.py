#!/usr/bin/env python3
"""Reproduce reviewed GameView construction and preUpdate forwarding slices."""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'


def recover(path):
    memory = ELFMemory(path)
    boundaries = [ ('disasm_load_gameview.txt', 0x780604, 0x7807c0),
                   ('disasm_gameview_preupdate.txt', 0x93ebd4, 0x93ec54)]
    gates = {name: verify_disassembly(memory, (NATIVE / name).read_text(), start, end)
             for name, start, end in boundaries}
    from elftools.elf.elffile import ELFFile
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = {s['st_value']: s.name for s in elf.get_section_by_name('.dynsym').iter_symbols()}
    base = (0x780614 + 8 + memory.word(0x7807bc)) & 0xffffffff
    class_slot = (base + memory.word(0x7807b8)) & 0xffffffff
    class_name = symbols.get(memory.word(class_slot))
    ivar_pointer = memory.word((base + memory.word(0x7807a4)) & 0xffffffff)
    ivar_name = symbols.get(ivar_pointer)
    if class_name != 'OBJC_CLASS_$_GameView' or ivar_name != 'OBJC_IVAR_$_EvolutionViewController.gameView':
        raise ValueError('unexpected constructor class/ivar')
    construction = []
    for call, literal, expected in (
        (0x7806bc, 0x7807b4, 'alloc'), (0x7806cc, 0x7807b0, 'init'),
        (0x780704, 0x7807ac, 'setViewController:'), (0x780718, 0x7807a0, 'view'),
        (0x78073c, 0x7807a8, 'setGameView:'), (0x78076c, 0x7807a0, 'view'),
        (0x78078c, 0x78079c, 'setGlView:')):
        selector = memory.selectors.get(memory.word((base + memory.word(literal)) & 0xffffffff))
        if selector != expected:
            raise ValueError(f'construction selector mismatch at {call:#x}')
        construction.append({'call': f'0x{call:08x}', 'selector': selector})
    pre_base = (0x93ebe4 + 8 + memory.word(0x93ec50)) & 0xffffffff
    world_pointer = memory.word((pre_base + memory.word(0x93ec4c)) & 0xffffffff)
    selector = memory.selectors.get(memory.word((pre_base + memory.word(0x93ec48)) & 0xffffffff))
    if symbols.get(world_pointer) != 'OBJC_IVAR_$_GameView.world' or selector != 'preUpdate:':
        raise ValueError('unexpected forwarding receiver/selector')
    with (NATIVE / 'refs_gameview_callbacks.tsv').open() as stream:
        counts = Counter(r['method'] for r in csv.DictReader(stream, delimiter='\t'))
    return {'verified_words': gates, 'constructed_class_symbol': class_name,
            'controller_ivar': ivar_name, 'controller_ivar_offset': memory.word(ivar_pointer),
            'construction_reviewed_calls': construction,
            'preupdate': {'call': '0x0093ec38', 'receiver_ivar': symbols[world_pointer],
                          'receiver_offset': memory.word(world_pointer), 'selector': selector,
                          'argument_reviewed': 'incoming r2 float bits -> s0 -> sp+4 -> s0 -> r3 -> r2; no arithmetic'},
            'callback_reference_counts_only': dict(sorted(counts.items())),
            'boundary': 'Reviewed static construction/forwarding only. alloc/init does not prove runtime dynamic class; world runtime identity and other callback bodies remain unverified.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = recover(args.elf)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
