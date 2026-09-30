#!/usr/bin/env python3
"""Byte-gated static map for World -[startTouch:tapCount:index:].

IMP 0x005b31b8 .. ARM.exidx end 0x005b3278 (48 words), PIC base 0x0105faf4
(same unit family as GameView -[init]/-[touchIsInUI:]). Types
c24@0:4{CGPoint=ff}8i16i20: CGPoint in r2/r3, the two ints at fp+8/fp+12.
The body is branch-free: one ivar zeroing store, then a tail objc_msgSend
forward to the uiManager with a signed-char passthrough. Every anchor is
re-verified against the SHA-256-pinned ELF; any drift aborts emission.
Static map only: no runtime receiver, nil-dispatch or side-effect proof.
"""
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
START, END = 0x005B31B8, 0x005B3278
EXPECTED_BASE = 0x0105FAF4
MSGSEND_STUB = 0x001C281C          # <objc_msgSend@plt>
MSGSEND_GOT_SLOT = 0x0105FB18      # R_ARM_JUMP_SLOT objc_msgSend

# PIC base: ldr r2,[pc,#0x78]@0x5b31ec ; add r2,pc,r2 @0x5b31f0.
BASE_LITERAL = 0x005B326C
BASE_ADD = 0x005B31F0

STORE_SITE = 0x005B3200            # str r3,[r0,r1] with r3=movw #0 at 0x5b31fc
FORWARD_SITE = 0x005B3258          # bl objc_msgSend stub

LITERAL_CELLS = {
    # word address -> (kind, expected)
    0x005B3268: ('ivar', 'OBJC_IVAR_$_World.pauseIdleTimer'),
    0x005B3270: ('ivar', 'OBJC_IVAR_$_World.uiManager'),
    0x005B3274: ('selector', 'startTouch:tapCount:index:'),
}


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_world_starttouch.txt').read_text()
    words = verify_disassembly(memory, text, START, END)
    base = (BASE_ADD + 8 + signed(memory.word(BASE_LITERAL))) & 0xffffffff
    if base != EXPECTED_BASE:
        raise ValueError(f'PIC base drift {base:#x}')
    if memory.imports.get(MSGSEND_GOT_SLOT) != 'objc_msgSend':
        raise ValueError('msgSend GOT slot evidence changed')

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = memory.data.find(b'\0', off, off + 256)
        return memory.data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    elf = ELFFile(io.BytesIO(path.read_bytes()))
    symbols = {s['st_value']: s.name
               for s in elf.get_section_by_name('.dynsym').iter_symbols()}
    ivars, selector = {}, None
    for cell, (kind, expected) in LITERAL_CELLS.items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        value = memory.word(slot)
        if kind == 'ivar':
            symbol = symbols.get(value, '')
            if symbol != expected:
                raise ValueError(f'ivar cell {cell:#x} drifted: {symbol}')
            ivars[expected.rsplit('.', 1)[1]] = {
                'cell': f'0x{cell:08x}', 'symbol': symbol,
                'offset': memory.word(value)}
        else:
            got = cstr(value)
            if got != expected:
                raise ValueError(f'selector cell {cell:#x} drifted: {got}')
            selector = {'cell': f'0x{cell:08x}', 'slot': f'0x{slot:08x}',
                        'name': got}
    return {
        'method': 'World -[startTouch:tapCount:index:]',
        'types': 'c24@0:4{CGPoint=ff}8i16i20',
        'elf_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'imp': f'0x{START:08x}',
        'arm_exidx_end': f'0x{END:08x}',
        'verified_words': words,
        'pic_base': f'0x{base:08x}',
        'branch_count': len([
            m for m in re.finditer(
                r'0x(005b3[0-9a-f]{3})\s+[0-9a-f]{8}\s+(b|beq|bne|bcs|bhs|bcc|blo|bmi|bpl|bvs|bvc|bhi|bls|bge|blt|bgt|ble)\s',
                text)]),
        'ivars': ivars,
        'forward_selector': selector,
        'store_site': f'0x{STORE_SITE:08x}',
        'forward_site': f'0x{FORWARD_SITE:08x}',
        'msgsend_stub': f'0x{MSGSEND_STUB:08x}',
        'sequence': [
            '0x5b31c4/8 load index@fp+12 into ip, tapCount@fp+8 into lr',
            '0x5b31cc..0x5b31e0 spill point.x(r2)/y(r3)/self(r0)/_cmd(r1) and '
            'the two ints to frame/stack',
            '0x5b31e4..0x5b3200 self->pauseIdleTimer (ivar offset 3264) = 0 '
            '(r3 = movw #0): touch start resets the server idle timer',
            '0x5b3204..0x5b3214 receiver = self->uiManager (ivar offset 240)',
            '0x5b3220..0x5b324c point x/y, tapCount, index staged per AAPCS '
            '(ints into [r4]/[r4,#4] via mov r4,sp; r0=uiManager, r1=sel)',
            '0x5b3258 bl objc_msgSend stub; 0x5b325c sxtb r0 passthrough; '
            'signed-char return is the CALLEE result unchanged',
        ],
        'claim': ('static branch-free body map; nil-receiver dispatch outcome '
                  'and uiManager internals are NOT proven here'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_starttouch.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_starttouch.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} branches={report['branch_count']} "
          f"forward={report['forward_selector']['name']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
