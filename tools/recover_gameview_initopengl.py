#!/usr/bin/env python3
"""Byte-gated, hand-reviewed GameView.initOpenGL call/literal map."""
import argparse
import csv
import json
import re
from pathlib import Path
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
# Explicitly reviewed r1/spill routes, NOT inferred by ordering a reference set.
CALL_LITERALS = {
    0x921874: 0x921e14, 0x921884: 0x921e10,
    0x9218d8: 0x921e00, 0x921908: 0x921e00, 0x921934: 0x921df4,
    0x921970: 0x921de0, 0x921980: 0x921dd8,
    0x921a10: 0x921de0, 0x921a20: 0x921dd8,
    0x921af0: 0x921dd0, 0x921b18: 0x921dc8,
    0x921b7c: 0x921e24, 0x921b98: 0x921e20,
    0x921c20: 0x921e3c, 0x921c30: 0x921e38,
    0x921c50: 0x921e30, 0x921c68: 0x921e2c,
    0x921d40: 0x921e30, 0x921d60: 0x921e58, 0x921d70: 0x921e54,
    0x921d84: 0x921e4c, 0x921d98: 0x921e4c, 0x921db8: 0x921e44,
}


def recover(path):
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_gameview_initopengl.txt').read_text()
    words = verify_disassembly(memory, text, 0x9216d0, 0x921e64)
    sites = {int(a, 16) for a in re.findall(r'(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+blx\s', text)}
    if sites != set(CALL_LITERALS):
        raise ValueError('reviewed call map does not exactly cover blx sites')
    base = (0x9216e0 + 8 + memory.word(0x921e60)) & 0xffffffff
    if memory.imports.get((base + memory.word(0x921dc4)) & 0xffffffff) != 'objc_msgSend':
        raise ValueError('unexpected dispatch relocation')
    calls = []
    for address, literal in sorted(CALL_LITERALS.items()):
        slot = (base + memory.word(literal)) & 0xffffffff
        selector = memory.selectors.get(memory.word(slot))
        if not selector:
            raise ValueError(f'unresolved selector {address:#x}')
        condition = 'unconditional within normal method execution'
        if address in (0x921b7c, 0x921b98):
            condition = 'totalGamePlayTimePassed < 1.0 (finite input)'
        elif address >= 0x921d40:
            condition = 'not(totalGamePlayTimePassed < 1.0) (finite input)'
        calls.append({'call': f'0x{address:08x}', 'literal': f'0x{literal:08x}',
                      'selector': selector, 'condition_reviewed': condition})
    with (NATIVE / 'refs_gameview_callbacks.tsv').open() as stream:
        resources = [r for r in csv.DictReader(stream, delimiter='\t')
                     if r['method'] == 'initOpenGL' and r['reference_kind'] == 'cfstring']
    # Verify CFString payloads, not merely the checked-in text labels.
    for row in resources:
        address = int(row['reference_address'], 16)
        pointer = memory.word(address + 8)
        length = memory.word(address + 12)
        offset = memory.offset(pointer, length) if pointer is not None and length is not None else None
        if offset is None or memory.data[offset:offset+length].decode('utf-8') != row['value']:
            raise ValueError('CFString payload mismatch')
    return {'verified_words': words, 'reviewed_call_count': len(calls), 'calls': calls,
            'resources_verified': [r['value'] for r in resources],
            'boundary': 'Hand-reviewed intact-frame static paths; not generic automated recovery or runtime GL/platform acceptance.'}


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
