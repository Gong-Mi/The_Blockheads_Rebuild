#!/usr/bin/env python3
"""Byte-gated, hand-reviewed GameView -[startTouch:withTouch:withEvent:] map.

IMP 0x0092be2c .. ARM.exidx end 0x0092c148 (199 words including the literal
pool), PIC base 0x0105faf4 (same compilation-unit family as -[init] and
-[touchIsInUI:]). Types v24@0:4{CGPoint=ff}8@16@20: CGPoint in r2/r3,
withTouch at fp+8, withEvent at fp+12 (withEvent is spilled but never read).

The checked-in listing is re-verified word-by-word against the SHA-256-pinned
ELF; every selector/ivar literal, dispatch site and branch below is anchored
to a verified address and the tool refuses to emit on any drift. Static
bounded-body map only: NOT runtime receiver identity, nil-dispatch outcome at
the UI touch object, or UIManager/World side-effect proof.
"""
import argparse
import io
import json
import re
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
START, END = 0x0092BE2C, 0x0092C148
EXPECTED_BASE = 0x0105FAF4
MSGSEND_STUB = 0x001C281C   # <objc_msgSend@plt>; slot 0x0105fb18
MSGSEND_JUMP_SLOT = 0x0105FB18
# Path-B indirect dispatch: GOT slot carries a GLOB_DAT against objc_msgSend
# (verified via relocation table, file value is 0).
MSGSEND_GLOB_DAT_SLOT = 0x0105B7A0

# Prologue materialises the PIC base: ldr ip,[pc,#0x304]@0x92be38 ;
# add ip,pc,ip@0x92be3c (add pc = 0x92be44).
BASE_LOAD = 0x0092BE38
BASE_LOAD_PC_OFFSET = 0x304
BASE_ADD = 0x0092BE3C

# Selector literal cells (word addresses; resolved through the PIC base).
SELECTOR_CELLS = {
    'tapCount': 0x0092C120,
    'startTouch:tapCount:': 0x0092C124,
    'startTouch:tapCount:index:': 0x0092C138,
    'touchIsInUI:': 0x0092C13C,
    'loadComplete': 0x0092C12C,
    'isSimulating': 0x0092C130,
}

# Ivar literal cells: word -> __objc_ivar entry address for GameView.<name>.
IVAR_CELLS = {
    'mainMenuUI': 0x0092C10C,
    'world': 0x0092C118,
    'primaryTouchIsActiveInUI': 0x0092C110,
    'startTouchHasntMoved': 0x0092C114,
    'startTouchPos': 0x0092C140,
}

EXPECTED_IVAR_OFFSETS = {
    'mainMenuUI': 20,
    'world': 24,
    'primaryTouchIsActiveInUI': 496,
    'startTouchHasntMoved': 486,
    'startTouchPos': 488,
}

# Reviewed dispatch sites: exactly the seven bl/blx instructions that send
# Objective-C messages in this body.
MSGSENDS = (
    (0x0092BF2C, 'bl stub', 'tapCount',
     'withTouch (fp-0x2c, first stack arg); menu path only'),
    (0x0092BF50, 'bl stub', 'startTouch:tapCount:',
     'mainMenuUI reloaded 0x0092bee4..0x0092befc; menu path iff '
     'mainMenuUI != nil AND world == nil (0x0092beb8 beq / 0x0092bee0 bne '
     'both route to the world path)'),
    (0x0092BF98, 'blx r2 (GOT objc_msgSend GLOB_DAT)', 'loadComplete',
     'world reloaded 0x0092bf70..0x0092bf84; reached when '
     'mainMenuUI == nil OR world != nil'),
    (0x0092BFE4, 'blx r2 (GOT objc_msgSend GLOB_DAT)', 'isSimulating',
     'world reloaded 0x0092bfbc..0x0092bfd0; reached when loadComplete '
     '(sxtb) != 0'),
    (0x0092C03C, 'bl stub', 'tapCount',
     'withTouch reloaded fp-0x2c; re-sent after the world gates'),
    (0x0092C068, 'bl stub', 'startTouch:tapCount:index:',
     'world reloaded 0x0092bff4..0x0092c00c; stack args [tapCount, 0] '
     '(index literal 0 via movw lr,#0@0x0092c058)'),
    (0x0092C0A8, 'bl stub', 'touchIsInUI:',
     'world kept from 0x0092c00c load; reached when isSimulating (sxtb) == 0'),
)

# Branch sites: (address, destination or None for linear, reviewed condition).
BRANCHES = (
    (0x0092BEB8, 0x0092BF5C, 'beq: self->mainMenuUI == nil -> world path'),
    (0x0092BEE0, 0x0092BF5C, 'bne: self->world != nil -> world path'),
    (0x0092BF58, 0x0092C104, 'b: menu startTouch:tapCount: done, return'),
    (0x0092BFA4, 0x0092C100, 'beq: loadComplete (sxtb) == 0 -> skip region'),
    (0x0092BFF0, 0x0092C100, 'bne: isSimulating (sxtb) != 0 -> skip region'),
    (0x0092C0B8, 0x0092C0FC, 'bne: touchIsInUI (sxtb) != 0 -> skip stores'),
    (0x0092C0FC, 0x0092C100, 'b: join into skip chain'),
    (0x0092C100, 0x0092C104, 'b: join into epilogue'),
)

# Byte/word stores with reviewed semantics.
STORES = (
    (0x0092BE8C, 'strb r7(=0)', 'self->startTouchHasntMoved = 0',
     'unconditional, before any gate'),
    (0x0092BE9C, 'strb r7(=0)', 'self->primaryTouchIsActiveInUI = 0',
     'unconditional, before any gate'),
    (0x0092C080, 'strb r0', 'self->primaryTouchIsActiveInUI = result byte',
     'NO sxtb by GameView: only the low byte of the World return is kept'),
    (0x0092C0DC, 'strb r2(=1)', 'self->startTouchHasntMoved = 1',
     'only when touchIsInUI (sxtb) == 0'),
    (0x0092C0F0, 'str r2', 'self->startTouchPos.x = point.x', 'full word'),
    (0x0092C0F8, 'str r2,[r0,#4]', 'self->startTouchPos.y = point.y',
     'full word'),
)


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_gameview_starttouch.txt').read_text()
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
        if symbol != f'OBJC_IVAR_$_GameView.{name}':
            raise ValueError(f'ivar cell drifted at {cell:#x}: {symbol}')
        offset = memory.word(entry)
        if offset != EXPECTED_IVAR_OFFSETS[name]:
            raise ValueError(f'ivar offset drifted for {name}: {offset}')
        ivars[name] = {'cell': f'0x{cell:08x}', 'symbol': symbol,
                       'offset': offset}

    # Dispatch machinery: plt stub slot and the path-B GLOB_DAT slot.
    if memory.imports.get(MSGSEND_JUMP_SLOT) != 'objc_msgSend':
        raise ValueError('msgSend JUMP_SLOT evidence changed')
    if memory.imports.get(MSGSEND_GLOB_DAT_SLOT) != 'objc_msgSend':
        raise ValueError('path-B msgSend GLOB_DAT slot evidence changed')

    # Instruction-level cross-check against the verified listing.
    rows = {}
    for line in text.splitlines():
        m = re.search(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', line)
        if m:
            rows[int(m[1], 16)] = m[2].strip()
    dispatch_sites = {s for s, _, _, _ in MSGSENDS}
    listed = {a for a, ins in rows.items()
              if re.match(r'^bl(x?)\s', ins)}
    if listed != dispatch_sites:
        raise ValueError(f'bl/blx site set drifted: {sorted(listed ^ dispatch_sites)}')
    for site, route, sel, _recv in MSGSENDS:
        ins = rows[site]
        if route == 'bl stub':
            if not re.match(rf'^bl #0x{MSGSEND_STUB:x}$', ins):
                raise ValueError(f'{site:#x} no longer bl msgSend stub: {ins}')
        else:
            if not re.match(r'^blx\s+r2$', ins):
                raise ValueError(f'{site:#x} no longer blx r2: {ins}')

    for site, _mn, effect, note in STORES:
        if not rows[site].startswith('str'):
            raise ValueError(f'{site:#x} no longer a store: {rows[site]}')

    return {
        'method': 'GameView -[startTouch:withTouch:withEvent:]',
        'implementation': f'0x{START:08x}',
        'arm_exidx_end': f'0x{END:08x}',
        'types': 'v24@0:4{CGPoint=ff}8@16@20',
        'verified_words': words,
        'pic_base': f'0x{base:08x}',
        'msgsend_stub': f'0x{MSGSEND_STUB:08x}',
        'msgsend_glob_dat_slot': f'0x{MSGSEND_GLOB_DAT_SLOT:08x}',
        'selectors': selectors,
        'ivars': ivars,
        'calls': [
            {'site': f'0x{site:08x}', 'route': route, 'selector': sel,
             'receiver_route': recv}
            for site, route, sel, recv in MSGSENDS
        ],
        'branches': [
            {'site': f'0x{site:08x}', 'target': f'0x{target:08x}',
             'condition': cond}
            for site, target, cond in BRANCHES
        ],
        'stores': [
            {'site': f'0x{site:08x}', 'instruction': mn, 'effect': effect,
             'note': note}
            for site, mn, effect, note in STORES
        ],
        'semantics': (
            'startTouchHasntMoved=0 and primaryTouchIsActiveInUI=0 execute '
            'before any gate. If mainMenuUI != nil AND world == nil: '
            '[mainMenuUI startTouch:point tapCount:[withTouch tapCount]]; '
            'return. Otherwise: [world loadComplete] (sxtb, nil dispatches '
            '0) returns early when 0; [world isSimulating] (sxtb) returns '
            'early when nonzero; re-send [withTouch tapCount]; '
            'primaryTouchIsActiveInUI = low byte of '
            '[world startTouch:point tapCount:tapCount index:0] (no sxtb); '
            'when [world touchIsInUI:point] (sxtb) == 0: '
            'startTouchHasntMoved=1 and startTouchPos=point (full words). '
            'withEvent argument is never read.'),
        'claim': ('static bounded-body map with per-instruction anchors; no '
                  'runtime receiver identity, nil-dispatch outcome or '
                  'UI/World side-effect proof'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'gameview_starttouch.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale gameview_starttouch.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} msgSends={len(report['calls'])} "
          f"branches={len(report['branches'])} ivars={len(report['ivars'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
