#!/usr/bin/env python3
"""Recover the bounded drawFrame temporary-background teardown from pinned ELF.

The opcode gates prevent a field-name match being mistaken for a proven store.
This does not establish generic heap/stack disjointness for the dataflow engine.
"""
import argparse
import json
from pathlib import Path
from trace_objc_dispatch import ELFMemory


def recover(path):
    memory = ELFMemory(path)
    # Exact ARM instructions from the checked-in bounded drawFrame disassembly.
    instructions = {
        0x781ad4: 0xe3000000,  # movw r0, 0
        0x781ad8: 0xe59f1388,  # ldr r1, [0x781e68]
        0x781adc: 0xe51b2034,  # ldr r2, [fp, -0x34]
        0x781ae0: 0xe7911002,  # ldr r1, [r1, r2]
        0x781b10: 0xe50b0038,  # str r0, [fp, -0x38] (save zero)
        0x781b18: 0xe50b103c,  # str r1, [fp, -0x3c] (ivar-offset pointer)
        0x781b50: 0xe51b001c,  # ldr r0, [fp, -0x1c] (self)
        0x781b54: 0xe51b103c,  # ldr r1, [fp, -0x3c]
        0x781b58: 0xe5912000,  # ldr r2, [r1] (ivar byte offset)
        0x781b5c: 0xe0800002,  # add r0, r0, r2
        0x781b60: 0xe51b2038,  # ldr r2, [fp, -0x38] (zero)
        0x781b64: 0xe5802000,  # str r2, [r0]
    }
    for address, expected in instructions.items():
        if memory.word(address) != expected:
            raise ValueError(f'ARM instruction mismatch at {address:#x}')
    base = (0x781a54 + 8 + memory.word(0x781eac)) & 0xffffffff
    slot = (base + memory.word(0x781e68)) & 0xffffffff
    pointer = memory.word(slot)
    offset = memory.word(pointer)
    from elftools.elf.elffile import ELFFile
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name('.dynsym')
        names = [s.name for s in symbols.iter_symbols() if s['st_value'] == pointer]
    expected_name = 'OBJC_IVAR_$_EvolutionViewController.tempBackgroundView'
    if expected_name not in names or offset != 44:
        raise ValueError('unexpected ivar identity/offset')
    return {
        'store_address': '0x00781b64', 'pic_base': f'0x{base:08x}',
        'ivar_got_slot': f'0x{slot:08x}', 'ivar_offset_address': f'0x{pointer:08x}',
        'ivar_symbol': expected_name, 'ivar_byte_offset': offset,
        'destination': 'entry receiver self + tempBackgroundView offset',
        'stored_value': 0, 'width_bytes': 4,
        'interpretation': 'clear tempBackgroundView after removeFromSuperview/release path',
        'boundary': 'static bounded slice; receiver-to-stack disjointness NOT established',
        'instruction_gate_count': len(instructions),
    }


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
