#!/usr/bin/env python3
"""Recover update entry gates/outgoing ABI; inventory unreviewed middle calls."""
import argparse
import json
import re
import struct
from pathlib import Path
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

NATIVE = Path(__file__).resolve().parents[1] / 'reconstruction/reverse-v3/native'


def expand_vfp_immediate(imm8, width):
    if not 0 <= imm8 <= 255 or width not in (32, 64):
        raise ValueError('invalid VFP immediate/width')
    exponent_bits, fraction_bits = (8, 23) if width == 32 else (11, 52)
    b6 = (imm8 >> 6) & 1
    exponent = ((1 - b6) << (exponent_bits - 1)) | (((1 << (exponent_bits - 3)) - 1) * b6 << 2) | ((imm8 >> 4) & 3)
    bits = ((imm8 >> 7) << (width - 1)) | (exponent << fraction_bits) | ((imm8 & 15) << (fraction_bits - 4))
    return struct.unpack('<f' if width == 32 else '<d', bits.to_bytes(width // 8, 'little'))[0]


def recover(path):
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_gameview_update.txt').read_text()
    words = verify_disassembly(memory, text, 0x9259c0, 0x928030)
    base = (0x9259d0 + 8 + memory.word(0x9268e8)) & 0xffffffff
    from elftools.elf.elffile import ELFFile
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = {s['st_value']: s.name for s in elf.get_section_by_name('.dynsym').iter_symbols()}
    fields = []
    for literal in (0x9268ec, 0x9268f0, 0x9268f4, 0x926b58, 0x928008, 0x92800c, 0x92801c, 0x926b68, 0x926b70):
        pointer = memory.word((base + memory.word(literal)) & 0xffffffff)
        name = symbols.get(pointer)
        if not name or not name.startswith('OBJC_IVAR_$_GameView.'):
            raise ValueError('missing field evidence')
        fields.append({'literal': f'0x{literal:08x}', 'symbol': name, 'offset': memory.word(pointer)})
    reviewed = {}
    for call, literal, expected in ((0x925c10, 0x926b54, 'loadComplete'),
                                    (0x925c5c, 0x926b5c, 'isSimulating'),
                                    (0x925d14, 0x926b6c, 'translatingToGoal'),
                                    (0x927fd4, 0x92802c, 'update:accurateDT:pinchScale:dragInProgress:')):
        name = memory.selectors.get(memory.word((base + memory.word(literal)) & 0xffffffff))
        if name != expected:
            raise ValueError('selector evidence changed')
        reviewed[call] = name
    calls = []
    for address in re.findall(r'(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+blx\s', text):
        address = int(address, 16)
        calls.append({'call': f'0x{address:08x}', 'selector_reviewed': reviewed.get(address),
                      'status': 'reviewed boundary slice' if address in reviewed else 'indexed only; middle semantics pending'})
    direct_reviewed = {0x925e7c: (0x926e08, 'translation'),
                       0x925f28: (0x926e10, 'setTranslation:'),
                       0x925f68: (0x926e08, 'translation'),
                       0x926000: (0x926fac, 'worldWidthMacro'),
                       0x926058: (0x926e08, 'translation'),
                       0x9260e4: (0x926e08, 'translation'),
                       0x926150: (0x926fac, 'worldWidthMacro')}
    for address, label in re.findall(r'(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+bl\s+([^\n]+)', text):
        address = int(address, 16)
        selector = None
        if address in direct_reviewed:
            literal, expected = direct_reviewed[address]
            selector = memory.selectors.get(memory.word((base + memory.word(literal)) & 0xffffffff))
            if selector != expected:
                raise ValueError('direct-call selector mismatch')
        word = memory.word(address)
        displacement = word & 0xffffff
        if displacement & 0x800000:
            displacement -= 1 << 24
        calls.append({'call': f'0x{address:08x}', 'kind': 'direct_bl',
                      'target_va': f'0x{(address + 8 + displacement * 4) & 0xffffffff:08x}',
                      'disassembly_target_label': label,
                      'selector_reviewed': selector,
                      'status': 'reviewed local selector route' if selector else 'indexed only; semantics pending'})
    for row in calls:
        row.setdefault('kind', 'indirect_blx')
    calls.sort(key=lambda row: int(row['call'], 16))
    constants = []
    for address, width in ((0x925a18, 32), (0x925a7c, 32), (0x925ab4, 64), (0x925d54, 32)):
        word = memory.word(address)
        imm8 = (((word >> 16) & 15) << 4) | (word & 15)
        constants.append({'instruction': f'0x{address:08x}', 'word': f'0x{word:08x}',
                          'immediate8': imm8, 'value': expand_vfp_immediate(imm8, width)})
    return {'verified_words': words, 'fields': fields, 'vfp_constants': constants,
            'call_count': len(calls),
            'indirect_call_count': sum(r['kind'] == 'indirect_blx' for r in calls),
            'direct_call_count': sum(r['kind'] == 'direct_bl' for r in calls),
            'reviewed_selector_route_count': sum(r['selector_reviewed'] is not None for r in calls),
            'inertia_stop_squared_speed': struct.unpack('<f', memory.word(0x9260ec).to_bytes(4, 'little'))[0],
            'calls': calls,
            'outgoing_abi_reviewed': {'r0': 'self.world', 'r2': 'dt saved at fp-0x28',
             'r3': 'accurateDT saved at fp-0x2c', 'stack0_double': 'self.pinchScale',
             'stack8_bool': 'self.scrolling || self.pinching'},
            'boundary': 'Entry gates and outgoing ABI reviewed; middle input/zoom logic not recovered. No runtime equivalence claim.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = recover(args.elf)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'calls'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
