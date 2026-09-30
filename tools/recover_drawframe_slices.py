#!/usr/bin/env python3
"""Reproduce reviewed drawFrame slices, not automatic receiver/alias recovery.

All reviewed instruction bytes are checked against the hash-pinned original ELF.
The call-to-literal/receiver paths are manually reviewed ARM slices, labelled as
such in output. No runtime observations or unconditional alias proof are claimed.
"""
import argparse
import json
import re
import struct
from pathlib import Path
from trace_objc_dispatch import ELFMemory

ROOT = Path(__file__).resolve().parents[1]
# call, selector literal, expected selector, receiver, bounded path/argument evidence
SLICES = [
    (0x781b28, 0x781e74, 'removeFromSuperview', 'self.tempBackgroundView', 'r1=lr; 0x781af4..0x781b28'),
    (0x781b4c, 0x781e70, 'release', 'self.tempBackgroundView', 'selref saved at fp-0x40; 0x781aec..0x781b4c'),
    (0x781bc4, 0x781e80, 'view', 'self', 'r1=[lr]; 0x781b88..0x781bc4'),
    (0x781bd4, 0x781e7c, 'setFramebuffer', 'return value of preceding view', 'r1=[[sp+0x40]]; r0 unchanged since view'),
    (0x781c40, 0x781e84, 'initOpenGL', 'self.gameView', 'r1=ip; 0x781c0c..0x781c40; only if openGLInitialized==0'),
    (0x781c98, 0x781e90, 'timeIntervalSinceReferenceDate', 'NSDate class import', 'r1=[r3]; 0x781c74..0x781c98'),
    (0x781db0, 0x781ea8, 'preUpdate:', 'self.gameView', 'r1=[sl]; r2=float bits from fp-0x2c'),
    (0x781de4, 0x781ea4, 'update:accurateDT:', 'self.gameView', 'r1=[[sp+0x20]]; r2 AND r3 load same fp-0x30'),
    (0x781e10, 0x781ea0, 'render:', 'self.gameView', 'r1=[[sp+0x18]]; r2=float bits from fp-0x30'),
    (0x781e3c, 0x781e80, 'view', 'self', 'r1=[[sp+0xc]]; self restored into r0'),
    (0x781e4c, 0x781e9c, 'presentFramebuffer', 'return value of preceding view', 'r1=[[sp+0x14]]; r0 unchanged since view'),
]


def verify_disassembly(memory, text, start=0x781a44, end=0x781eb0):
    rows = re.findall(r'\b(0x[0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+', text)
    addresses = []
    for address, raw in rows:
        address = int(address, 16)
        expected = int.from_bytes(bytes.fromhex(raw), 'little')
        if memory.word(address) != expected:
            raise ValueError(f'disassembly bytes differ at {address:#x}')
        addresses.append(address)
    if len(addresses) != len(set(addresses)) or set(addresses) != set(range(start, end, 4)):
        raise ValueError('disassembly does not exactly cover bounded function and literal pool')
    return len(addresses)


def recover(path):
    memory = ELFMemory(path)
    text = (ROOT / 'reconstruction/reverse-v3/native/disasm_draw_frame.txt').read_text()
    words = verify_disassembly(memory, text)
    base = (0x781a54 + 8 + memory.word(0x781eac)) & 0xffffffff
    target_slot = (base + memory.word(0x781e6c)) & 0xffffffff
    if memory.imports.get(target_slot) != 'objc_msgSend':
        raise ValueError('dispatch target relocation changed')
    calls = []
    for address, literal, expected, receiver, route in SLICES:
        slot = (base + memory.word(literal)) & 0xffffffff
        name = memory.selectors.get(memory.word(slot))
        if name != expected:
            raise ValueError(f'selector mismatch at {address:#x}: {name!r}')
        calls.append({'call': f'0x{address:08x}', 'selector_literal': f'0x{literal:08x}',
                      'selref': f'0x{slot:08x}', 'selector': name,
                      'receiver_reviewed': receiver, 'route_reviewed': route,
                      'evidence_kind': 'reviewed bounded static slice, not runtime verified'})
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = {s['st_value']: s.name for s in elf.get_section_by_name('.dynsym').iter_symbols()}
        ivars = []
        for literal in (0x781e5c, 0x781e60, 0x781e64, 0x781e68, 0x781e78, 0x781e8c):
            slot = (base + memory.word(literal)) & 0xffffffff
            pointer = memory.word(slot)
            ivars.append({'literal': f'0x{literal:08x}', 'symbol': symbols.get(pointer),
                          'offset': memory.word(pointer)})
        class_slot = (base + memory.word(0x781e94)) & 0xffffffff
        class_names = []
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                for rel in section.iter_relocations():
                    if rel['r_offset'] == class_slot and rel['r_info_type'] == 2:
                        class_names.append(elf.get_section(section['sh_link']).get_symbol(rel['r_info_sym']).name)
        if class_names != ['OBJC_CLASS_$_NSDate']:
            raise ValueError('NSDate R_ARM_ABS32 class relocation mismatch')
    return {'instruction_words_verified': words, 'call_count': len(calls), 'calls': calls,
            'ivars': ivars, 'max_dt_f32': struct.unpack('<f', memory.word(0x781e88).to_bytes(4, 'little'))[0],
            'negative_dt_fallback_f32': struct.unpack('<f', memory.word(0x781e98).to_bytes(4, 'little'))[0],
            'boundary': 'Hand-reviewed local register/spill paths under normal intact-frame execution; not a generic alias proof or automatic 11-call recovery.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = recover(args.elf)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'verified_words': result['instruction_words_verified'], 'reviewed_calls': result['call_count'],
                      'selectors': [r['selector'] for r in result['calls']]}, ensure_ascii=False))


if __name__ == '__main__':
    main()
