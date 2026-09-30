#!/usr/bin/env python3
"""Byte-gated, hand-reviewed GameView -[touchIsInUI:] evidence map.

IMP 0x0092bc54 .. ARM.exidx end 0x0092be2c (118 words), PIC base 0x0105faf4
(same compilation unit family as -[init]). The checked-in listing is re-verified
word-by-word against the SHA-256-pinned ELF; every selector/ivar literal, call
site and branch target below is anchored to a verified address and the tool
refuses to emit on any drift. Static control-flow map only: NOT runtime
receiver identity or UI-state side effects.
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
START, END = 0x0092BC54, 0x0092BE2C
EXPECTED_BASE = 0x0105FAF4
MSGSEND_STUB = 0x001C281C   # objdump: <objc_msgSend@plt>; slot 0x105fb18
                            # R_ARM_JUMP_SLOT objc_msgSend (both re-checked below)

# Prologue materialises the PIC base: ldr ip,[pc,#0x1c0]@0x92bc60 ; add ip,pc,ip.
BASE_LOAD = 0x0092BC60
BASE_LOAD_PC_OFFSET = 0x1C0
BASE_ADD = 0x0092BC64

# Selector literal cells (slot word addresses; resolved through PIC base).
SELECTOR_CELLS = {
    'touchIsInUI:': 0x0092BE14,
    'loadComplete': 0x0092BE1C,
    'isSimulating': 0x0092BE20,
}
# Ivar literal cells: word -> __objc_ivar entry address for GameView.<name>.
IVAR_CELLS = {
    'mainMenuUI': 0x0092BE08,
    'world': 0x0092BE0C,
}

# Reviewed dispatch sites: exactly the four bl/blx instructions that send
# Objective-C messages in this body (see verify in recover()).
MSGSENDS = (
    # (site, route, selector_cell, receiver route reviewed from loads)
    (0x0092BD04, 'bl stub', 'touchIsInUI:',
     'mainMenuUI (self+ivar): loaded 0x0092bc80..0x0092bc90; path taken iff '
     'mainMenuUI != nil AND world == nil (0x0092bc9c beq / 0x0092bcc4 bne both '
     'jump to the world path otherwise)'),
    (0x0092BD4C, 'blx r2 (GOT objc_msgSend)', 'loadComplete',
     'world reloaded 0x0092bd24..0x0092bd3c; reached from 0x0092bd10 '
     '(mainMenuUI==nil OR world!=nil)'),
    (0x0092BD98, 'blx r2 (GOT objc_msgSend)', 'isSimulating',
     'world reloaded 0x0092bd70..0x0092bd84 (0x0092bd88 loads the selector); '
     'reached when loadComplete != 0'),
    (0x0092BDE4, 'bl stub', 'touchIsInUI:',
     'world loaded 0x0092bda8..0x0092bdc0; reached when isSimulating == 0'),
)

# Branch sites: (address, destination or None-for-linear, reviewed condition).
BRANCHES = (
    (0x0092BC9C, 0x0092BD10, 'beq: self->mainMenuUI == nil -> world path'),
    (0x0092BCC4, 0x0092BD10, 'bne: self->world != nil -> world path'),
    (0x0092BD0C, 0x0092BDFC, 'b: mainMenuUI result stored, return path'),
    (0x0092BD58, 0x0092BDF0, 'beq: loadComplete (sxtb) == 0 -> constant 0'),
    (0x0092BDA4, 0x0092BDF0, 'bne: isSimulating (sxtb) != 0 -> constant 0'),
    (0x0092BDEC, 0x0092BDFC, 'b: world touchIsInUI result, return path'),
    (0x0092BDF0, 0x0092BDF4, 'b: padding fallthrough into movw r0,#0'),
)

SITES = {a for a, _, _ in BRANCHES} | {s for s, _, _, _ in MSGSENDS}


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_gameview_touchisinui.txt').read_text()
    words = verify_disassembly(memory, text, START, END)

    literal = (BASE_LOAD + 8 + BASE_LOAD_PC_OFFSET) & 0xffffffff
    base = (BASE_ADD + 8 + signed(memory.word(literal))) & 0xffffffff
    if base != EXPECTED_BASE:
        raise ValueError(f'PIC base drift {base:#x}')

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = memory.data.find(b'\0', off, off + 256)
        return memory.data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    elf = ELFFile(io.BytesIO(path.read_bytes()))
    symbols = {s['st_value']: s.name
               for s in elf.get_section_by_name('.dynsym').iter_symbols()}

    selectors = {}
    for name, cell in SELECTOR_CELLS.items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        got = cstr(memory.word(slot))
        if got != name:
            raise ValueError(f'selector cell drifted at {cell:#x}: {got}')
        selectors[name] = {'cell': f'0x{cell:08x}', 'slot': f'0x{slot:08x}'}

    ivars = {}
    for name, cell in IVAR_CELLS.items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        entry = memory.word(slot)
        symbol = symbols.get(entry, '')
        if not symbol.startswith('OBJC_IVAR_$_GameView.'):
            raise ValueError(f'ivar cell drifted at {cell:#x}: {symbol}')
        ivars[name] = {'cell': f'0x{cell:08x}', 'symbol': symbol,
                       'offset': memory.word(entry)}

    # msgSend stub sanity: the bl sites target MSGSEND_STUB whose JUMP_SLOT
    # relocation (or GOT import table) says objc_msgSend.
    if memory.imports.get(0x105FB18) != 'objc_msgSend':
        raise ValueError('msgSend GOT slot evidence changed')
    stub = memory.word(MSGSEND_STUB)
    if stub is None:
        raise ValueError('stub unreadable')

    # Instruction-level cross-check against the verified listing.
    rows = {}
    for line in text.splitlines():
        m = re.search(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', line)
        if m:
            rows[int(m[1], 16)] = m[2].strip().replace('#', '')
    dispatch_sites = {s for s, _, _, _ in MSGSENDS}
    listed = {a for a, ins in rows.items()
              if re.match(r'^bl(x?)\s', ins) and a in rows}
    if listed != dispatch_sites:
        raise ValueError(f'bl/blx site set drifted: {sorted(listed ^ dispatch_sites)}')
    for site, route, sel, _recv in MSGSENDS:
        ins = rows[site]
        if route == 'bl stub':
            m = re.match(r'^bl\s+(0x[0-9a-f]+)$', ins)
            if not m or int(m[1], 16) != MSGSEND_STUB:
                raise ValueError(f'{site:#x} no longer calls the msgSend stub: {ins}')
        else:
            if not re.match(r'^blx\s+r2$', ins):
                raise ValueError(f'{site:#x} no longer blx r2: {ins}')
    for addr, dest, _cond in BRANCHES:
        ins = rows.get(addr, '')
        m = re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)
        if not m or int(m[2], 16) != dest:
            raise ValueError(f'branch {addr:#x} drifted: {ins!r} -> {dest:#x}')

    calls = [{'site': f'0x{s:08x}', 'route': r, 'selector': sel,
              'receiver_route': recv} for s, r, sel, recv in MSGSENDS]
    return {
        'method': 'GameView -[touchIsInUI:]',
        'types': 'c16@0:4{CGPoint=ff}8',
        'elf_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'imp': f'0x{START:08x}',
        'arm_exidx_end': f'0x{END:08x}',
        'verified_words': words,
        'pic_base': f'0x{base:08x}',
        'msgsend_stub': f'0x{MSGSEND_STUB:08x}',
        'msgsend_got_slot': '0x0105fb18',
        'selectors': selectors,
        'ivars': ivars,
        'calls': calls,
        'branches': [{'address': f'0x{a:08x}', 'destination': f'0x{d:08x}',
                      'condition': c} for a, d, c in BRANCHES],
        'decision': (
            'world-path (mainMenuUI==nil OR world!=nil): '
            'return 0 unless [world loadComplete] && ![world isSimulating], '
            'then return [world touchIsInUI:point]; '
            'menu-path (mainMenuUI!=nil AND world==nil): '
            'return [mainMenuUI touchIsInUI:point]. '
            'Result byte is strb-stored and ldrsb-returned (signed char).'),
        'claim': ('static bounded-body map with per-instruction anchors; no '
                  'runtime receiver identity, nil-dispatch outcome or UI-state '
                  'side-effect proof'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'gameview_touchisinui.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale gameview_touchisinui.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} msgSends={len(report['calls'])} "
          f"branches={len(report['branches'])} ivars={len(report['ivars'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
