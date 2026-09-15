#!/usr/bin/env python3
"""Byte-gated, hand-reviewed GameView -[cancelTouch:] evidence map.

IMP 0x0092c638 .. ARM.exidx end 0x0092c89c (153 words including literal pool),
PIC base 0x0105faf4 (same compilation unit family as -[init]/-[touchIsInUI:]).
The checked-in listing is re-verified word-by-word against the SHA-256-pinned
ELF; every selector/ivar literal, call site and branch target below is
anchored to a verified address and the tool refuses to emit on any drift.
Static control-flow map only: NOT runtime receiver identity, nil-dispatch
outcome, or touch-state side-effect proof.
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
START, END = 0x0092C638, 0x0092C89C
EXPECTED_BASE = 0x0105FAF4
MSGSEND_STUB = 0x001C281C   # objc_msgSend@plt; GOT JUMP_SLOT 0x105fb18
MSGSEND_GOT_SLOT = 0x0105B7A0  # import slot reloaded for both blx r2 sites

# Prologue materialises the PIC/GOT base: ldr ip,[0x0092c898] ; add ip,pc,ip.
BASE_LOAD = 0x0092C644
BASE_LITERAL = 0x0092C898
BASE_ADD = 0x0092C648

# Selector literal cells (slot word addresses; resolved through GOT base).
SELECTOR_CELLS = {
    'endTouch:': 0x0092C874,
    'loadComplete': 0x0092C87C,
    'isSimulating': 0x0092C880,
    'cancelTouch:index:': 0x0092C890,
}
# Ivar literal cells: word -> GOT slot -> __objc_ivar entry for GameView.<name>.
IVAR_CELLS = {
    'mainMenuUI': 0x0092C868,
    'world': 0x0092C86C,
    'startTouchHasntMoved': 0x0092C894,
    'primaryTouchIsActiveInUI': 0x0092C884,
    'secondaryTouchIsActiveInUI': 0x0092C888,
}
# Expected GOT slots the ivar cells resolve through (cross-checked in recover).
IVAR_SLOTS = {
    'mainMenuUI': 0x0105E168,
    'world': 0x0105E110,
    'startTouchHasntMoved': 0x0105E20C,
    'primaryTouchIsActiveInUI': 0x0105E208,
    'secondaryTouchIsActiveInUI': 0x0105E214,
}

# Reviewed dispatch sites: exactly the four bl/blx instructions that send
# Objective-C messages in this body (see verify in recover()).
MSGSENDS = (
    # (site, route, selector, receiver route reviewed from loads)
    (0x0092C6E8, 'bl stub', 'endTouch:',
     'mainMenuUI (self+ivar): loaded 0x0092c6ac..0x0092c6c4 through cells '
     '0x0092c868/0x0092c870 ([r1,r2] arithmetic lands on GOT slot 0x0105e168); '
     'path taken iff mainMenuUI != nil AND world == nil (0x0092c680 beq / '
     '0x0092c6a8 bne both jump to the world path otherwise)'),
    (0x0092C72C, 'blx r2 (GOT objc_msgSend)', 'loadComplete',
     'world (self+ivar): loaded 0x0092c704..0x0092c718 via GOT slot 0x0105e110; '
     'reached from 0x0092c680 (mainMenuUI==nil) or 0x0092c6a8 (world!=nil)'),
    (0x0092C778, 'blx r2 (GOT objc_msgSend)', 'isSimulating',
     'world reloaded 0x0092c750..0x0092c764 via GOT slot 0x0105e110; reached '
     'when loadComplete (sxtb) != 0 (0x0092c738 beq falls through)'),
    (0x0092C818, 'bl stub', 'cancelTouch:index:',
     'world reloaded 0x0092c7d4..0x0092c7e8 ([r1,r2] lands on GOT slot '
     '0x0105e110); reached when primaryTouchIsActiveInUI != 0 (bne 0x0092c7a8) '
     'OR both UI-active bytes == 0; third argument index=0 is materialised by '
     'movw lr,0 + str lr,[ip] at 0x0092c810..0x0092c814'),
)

# Branch sites: (address, destination, reviewed condition).
BRANCHES = (
    (0x0092C680, 0x0092C6F0, 'beq: self->mainMenuUI == nil -> world path'),
    (0x0092C6A8, 0x0092C6F0, 'bne: self->world != nil -> world path'),
    (0x0092C6EC, 0x0092C840, 'b: menu endTouch: send done -> shared tail'),
    (0x0092C738, 0x0092C83C, 'beq: loadComplete (sxtb) == 0 -> tail, world send skipped'),
    (0x0092C784, 0x0092C83C, 'bne: isSimulating (sxtb) != 0 -> tail, world send skipped'),
    (0x0092C7A8, 0x0092C7D0, 'bne: primaryTouchIsActiveInUI != 0 -> world cancelTouch send'),
    (0x0092C7CC, 0x0092C81C, 'bne: secondaryTouchIsActiveInUI != 0 -> skip send, '
                            'clear startTouchHasntMoved'),
    (0x0092C83C, 0x0092C840, 'b: join -> shared tail'),
)


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site, word):
    """Decode an unconditional ARM bl immediate from the verified word."""
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not a bl immediate form: {word:#x}')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xFFFFFFFF


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_gameview_canceltouch.txt').read_text()
    words = verify_disassembly(memory, text, START, END)

    base = (BASE_ADD + 8 + signed(memory.word(BASE_LITERAL))) & 0xffffffff
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
        if slot != IVAR_SLOTS[name]:
            raise ValueError(f'ivar cell {cell:#x} resolved to {slot:#x}, '
                             f'expected {IVAR_SLOTS[name]:#x}')
        entry = memory.word(slot)
        symbol = symbols.get(entry, '')
        if not symbol.startswith('OBJC_IVAR_$_GameView.'):
            raise ValueError(f'ivar cell drifted at {cell:#x}: {symbol}')
        ivars[name] = {'cell': f'0x{cell:08x}', 'slot': f'0x{slot:08x}',
                       'symbol': symbol, 'offset': memory.word(entry)}

    # msgSend stub sanity: the bl sites decode (from verified bytes) to
    # MSGSEND_STUB whose JUMP_SLOT relocation says objc_msgSend; the blx r2
    # sites reload objc_msgSend from GOT import slot MSGSEND_GOT_SLOT.
    if memory.imports.get(0x105FB18) != 'objc_msgSend':
        raise ValueError('msgSend JUMP_SLOT evidence changed')
    if memory.imports.get(MSGSEND_GOT_SLOT) != 'objc_msgSend':
        raise ValueError('msgSend GOT reload slot evidence changed')

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
            target = bl_target(site, memory.word(site))
            if target != MSGSEND_STUB:
                raise ValueError(f'{site:#x} bl targets {target:#x}, '
                                 f'expected stub {MSGSEND_STUB:#x} ({ins})')
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
        'method': 'GameView -[cancelTouch:]',
        'types': 'v16@0:4{CGPoint=ff}8',
        'elf_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'imp': f'0x{START:08x}',
        'arm_exidx_end': f'0x{END:08x}',
        'verified_words': words,
        'pic_base': f'0x{base:08x}',
        'msgsend_stub': f'0x{MSGSEND_STUB:08x}',
        'msgsend_got_slot': f'0x{MSGSEND_GOT_SLOT:08x}',
        'selectors': selectors,
        'ivars': ivars,
        'calls': calls,
        'branches': [{'address': f'0x{a:08x}', 'destination': f'0x{d:08x}',
                      'condition': c} for a, d, c in BRANCHES],
        'decision': (
            'menu-path (mainMenuUI!=nil AND world==nil): '
            '[mainMenuUI endTouch:point], then shared tail. '
            'world-path: unless [world loadComplete] (sxtb) != 0 AND '
            '[world isSimulating] (sxtb) == 0, skip to tail (0x0092c738 beq / '
            '0x0092c784 bne). Gated block: if primaryTouchIsActiveInUI != 0 OR '
            '(primary==0 AND secondary==0): [world cancelTouch:point index:0] '
            'with index argument 0; if primary==0 AND secondary!=0: send '
            'skipped. Either way startTouchHasntMoved = 0 (strb at 0x0092c838, '
            'reached by fall-through from the send AND by bne 0x0092c7cc). '
            'Shared tail always stores 0 to primaryTouchIsActiveInUI '
            '(strb at 0x0092c85c). Returns void.'),
        'claim': ('static bounded-body map with per-instruction anchors; no '
                  'runtime receiver identity, nil-dispatch outcome or '
                  'touch-state side-effect proof'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'gameview_canceltouch.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale gameview_canceltouch.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} msgSends={len(report['calls'])} "
          f"branches={len(report['branches'])} ivars={len(report['ivars'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
