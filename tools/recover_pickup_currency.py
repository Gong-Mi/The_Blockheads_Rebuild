#!/usr/bin/env python3
"""Recover the Blockhead currency-split region (type 0x12a) as a static
manifest: CFG-based code/data split, every pc-relative literal resolved to a
selector / ivar-offset symbol / class ref / import / unmapped runtime object,
plus PLT stub targets and internal edges. Static only: no execution claim.

Supersedes the POOLS list in recover_inventory_pickup.py for this region,
which mislabelled code words as pool data.
"""
import argparse, hashlib, json, re, struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
START, END = 0xc61c00, 0xc638a0
CURRENCY_START, CURRENCY_END = 0xc629b0, 0xc63340


def main():
    p = argparse.ArgumentParser(); p.add_argument('--elf', type=Path, required=True)
    p.add_argument('--check', action='store_true'); a = p.parse_args()
    blob = a.elf.read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA, 'ELF SHA mismatch'
    with a.elf.open('rb') as f:
        elf = ELFFile(f)
        segs = [(s['p_vaddr'], s.data()) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        dyn = {}
        for sec in elf.iter_sections():
            if sec['sh_type'] == 'SHT_DYNSYM':
                for s in sec.iter_symbols():
                    dyn.setdefault(s['st_value'], []).append(s.name)
        rels = {}
        for sec in elf.iter_sections():
            if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
                tab = elf.get_section(sec['sh_link'])
                for r in sec.iter_relocations():
                    rels[r['r_offset']] = (r['r_info_type'], tab.get_symbol(r['r_info_sym']).name)

    def read(addr, n):
        for base, data in segs:
            if base <= addr and addr + n <= base + len(data):
                return data[addr - base:addr - base + n]
        raise ValueError('not file-backed ' + hex(addr))

    def word(addr): return struct.unpack('<I', read(addr, 4))[0]

    def cstr(addr, cap=160):
        raw = bytearray()
        try:
            for _ in range(cap):
                b = read(addr + len(raw), 1)
                if b == b'\0': break
                raw += b
        except ValueError:
            return None
        s = raw.decode(errors='replace')
        return s if raw and all(32 <= ord(c) < 127 for c in s) else None

    # The method's PIC base literal (verified by recover_inventory_pickup.py).
    PIC = (0xc61c14 + 8 + word(0xc62bb8)) & 0xffffffff

    # ---- CFG code/data split -------------------------------------------
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    # Pass 0: any word referenced by a pc-relative load is a pool literal,
    # never an instruction (capstone happily decodes pool words such as the
    # PIC base at 0xc62bb8 as ldrsbteq; reachability fall-through must not
    # resurrect them as code).
    literal_words = set()
    for x in range(START, END, 4):
        ins = list(md.disasm(struct.pack('<I', word(x)), x))
        if len(ins) == 1 and '[pc, #' in ins[0].op_str and ins[0].mnemonic in ('ldr', 'ldrb', 'ldrsb', 'ldrd'):
            imm = int(ins[0].op_str.rsplit('#', 1)[1].rstrip(']'), 0)
            lit = (x + 8 + imm) & 0xffffffff
            if START <= lit < END:
                literal_words.add(lit)
    code, edges, seen, work = {}, [], {START}, [START]
    def decode(addr):
        if addr in literal_words:
            return None
        i = list(md.disasm(struct.pack('<I', word(addr)), addr))
        return i[0] if len(i) == 1 else None
    while work:
        addr = work.pop()
        while addr < END and addr not in code:
            i = decode(addr)
            if i is None: break
            code[addr] = i; m = i.mnemonic; nxt = addr + 4
            if re.fullmatch(r'b(cc|cs|eq|ne|vs|vc|mi|pl|ge|lt|gt|le|al)?', m) and i.op_str.startswith('#'):
                t = int(i.op_str[1:], 16)
                edges.append((addr, t, 'cond')); edges.append((addr, nxt, 'fall'))
                seen.add(nxt); work.append(nxt); seen.add(t); work.append(t); break
            if m == 'b' and i.op_str.startswith('#'):
                t = int(i.op_str[1:], 16); edges.append((addr, t, 'jump'))
                seen.add(t); work.append(t); break
            if m == 'bl' and i.op_str.startswith('#'):
                t = int(i.op_str[1:], 16); edges.append((addr, t, 'call'))
                if t == START: break
                addr = nxt; continue
            if m == 'bx' and 'lr' in i.op_str: break
            if m == 'blx' and i.op_str.startswith('r'): edges.append((addr, None, 'indirect')); addr = nxt; continue
            if m == 'pop' and 'pc' in i.op_str: break
            addr = nxt
            if addr in code: break
    data = [x for x in range(START, END, 4) if x not in code]
    runs = []
    for x in data:
        if runs and x == runs[-1][1] + 4: runs[-1][1] = x
        else: runs.append([x, x])
    pools = [(s, e + 4) for s, e in runs]

    # ---- pc-relative literal resolution --------------------------------
    lit_pat = re.compile(r'^(?:ldr|ldrsb|ldrb)\s+(\w+),\s*\[pc, #(\w+)\]')
    def resolve_slot(slot):
        out = {'slot': hex(slot)}
        if not any(b <= slot < b + len(d) for b, d in segs):
            return {**out, 'kind': 'unmapped-slot'}
        info = rels.get(slot)
        try: pointed = word(slot)
        except ValueError: return {**out, 'kind': 'unmapped'}
        # GOT anchor computation: a literal whose PIC-relative value lands on
        # the anchor itself (the pc-form `add rN,pc,rN` recompute at the next
        # instruction proves it; these are NOT data references).
        if slot == PIC:
            return {**out, 'kind': 'got-anchor-literal'}
        if info and info == (21, 'objc_msgSend'):
            return {**out, 'kind': 'import', 'target': 'objc_msgSend'}
        if info and info[0] == 21:
            return {**out, 'kind': 'import', 'target': info[1]}
        name = cstr(pointed)
        if name and info is None:
            return {**out, 'kind': 'selector', 'selector': name}
        if info and info[0] == 2:  # R_ARM_ABS32
            # On REL relocations the file word is the addend; 0 means the
            # runtime fills the slot with the relocation symbol's address.
            if pointed == 0:
                extra = {}
                if info[1] == '__CFConstantStringClassReference':
                    # The slot itself is the CFString struct: [class,flags,
                    # char* data, len] with data/len file-backed constants.
                    try:
                        dp, ln = word(slot + 8), word(slot + 12)
                        if 0 < ln < 64:
                            extra['cfstring'] = cstr(dp, ln)
                    except (ValueError, struct.error):
                        pass
                return {**out, 'kind': 'relocated-at-load', 'reloc': info[1], **extra}
            syms = [n for n in dyn.get(pointed, []) if n]
            return {**out, 'kind': 'class-ref', 'reloc': info[1], 'word': hex(pointed)} if not syms else {**out, 'kind': 'reloc-absolute', 'symbols': syms, 'word': hex(pointed)}
        if info and info[0] == 23:
            syms = [n for v, names in dyn.items() if v == pointed for n in names if n.startswith('OBJC_IVAR_$')]
            if syms:
                return {**out, 'kind': 'ivar', 'symbol': syms[0], 'offset': hex(word(pointed))}
            s2 = cstr(pointed)
            if s2: return {**out, 'kind': 'selector', 'selector': s2}
            cf = any(v == pointed and '__CFConstantStringClassReference' in names for v, names in dyn.items())
            payload = None
            try:
                dp, ln = word(pointed + 8), word(pointed + 12)
                if 0 < ln < 64:
                    payload = cstr(dp, ln)
            except (ValueError, struct.error):
                pass
            return {**out, 'kind': 'data', 'word': hex(pointed), 'cfstring_ref': cf,
                    'cfstring': payload,
                    'unmapped_target': not any(b <= pointed < b + len(d) for b, d in segs)}
        syms = [n for n in dyn.get(pointed, []) if n]
        if syms:
            return {**out, 'kind': 'symbol', 'symbols': [s for s in syms if s], 'word': hex(pointed)}
        return {**out, 'kind': 'raw', 'word': hex(pointed)}

    annotated, sends, stubs, ivar_reads = [], [], {}, {}
    def pc_rematerialize(addr):
        """True if the insn following a ldr[pc] is `add <same reg>, pc, <reg>`,
        i.e. the literal is a GOT-anchor (PIC base) recompute, not a slot
        offset read via [slot, base]."""
        i = code.get(addr + 4)
        if i is None or i.mnemonic != 'add':
            return None
        regs = [t.strip() for t in i.op_str.split(',')]
        want = code[addr].op_str.split(',')[0].strip()
        if len(regs) == 3 and regs[1] == 'pc' and regs[0] == want and regs[2] == want:
            return (addr + 4 + 8) & 0xffffffff
        return None
    for addr in sorted(code):
        i = code[addr]; text = f'{i.mnemonic} {i.op_str}'
        note = ''
        mm = lit_pat.match(text.replace('!,', ',')) or lit_pat.match(text)
        if mm:
            reg, imm = mm.group(1), int(mm.group(2), 0)
            lit = (addr + 8 + imm) & 0xffffffff
            try:
                pool_word = word(lit)
                remat = pc_rematerialize(addr)
                if remat is not None:
                    anchor = (remat + pool_word) & 0xffffffff
                    info = {'slot': hex(anchor), 'kind': 'got-anchor-recompute',
                            'matches_pic_base': anchor == PIC}
                    note = f'  ;pool {lit:08x} ' + json.dumps(info, sort_keys=True)
                else:
                    slot = (PIC + pool_word) & 0xffffffff
                    info = resolve_slot(slot)
                    ivar_reads[reg] = (lit, slot, info)
                    note = f'  ;pool {lit:08x} slot {slot:#x} ' + json.dumps(info, sort_keys=True)
            except ValueError:
                note = f'  ;pool {lit:08x} unreadable'
        elif i.mnemonic == 'add' and 'r2, r2, r' not in i.op_str and text.startswith('add'):
            pass
        elif i.mnemonic in ('bl', 'blx') and i.op_str.startswith('#'):
            t = int(i.op_str[1:], 16)
            tgt = [n for v, names in dyn.items() if v == t for n in names if n]
            label = 'method-internal' if START <= t < END else ('plt-stub' if t < 0x300000 else 'helper')
            note = f'  ;-> {t:#x} {tgt or label}'
            if label == 'plt-stub':
                # resolve GOT jump: add ip,pc,#hi; add ip,ip,#lo; ldr pc,[ip,#off]!
                try:
                    s0, s1, s2 = decode(t), decode(t + 4), decode(t + 8)
                    if s0 and s0.mnemonic == 'add' and s1 and s1.mnemonic == 'add' and s2 and s2.mnemonic == 'ldr':
                        def modimm(insn_word):
                            # ARM 8-bit immediate rotated by 2*n.
                            imm = insn_word & 0xff; rot = ((insn_word >> 8) & 0xf) * 2
                            return ((imm >> rot) | (imm << (32 - rot))) & 0xffffffff if rot else imm
                        w0 = word(t); w1 = word(t + 4)
                        h = modimm(w0 & 0xfff); lo = modimm(w1 & 0xfff)
                        off = re.search(r'#(\w+)\]!', s2.op_str)
                        base = (t + 8 + h + lo) & 0xffffffff
                        got = (base + int(off.group(1), 16)) & 0xffffffff
                        names = rels.get(got)
                        stubs[hex(t)] = {'got': hex(got), 'import': names[1] if names else None}
                        note += f' GOT {got:#x} {names}'
                except Exception:
                    pass
            sends.append(dict(address=hex(addr), target=hex(t), label=label,
                              symbols=tgt, stub=stubs.get(hex(t))))
        elif i.mnemonic == 'blx' and i.op_str.startswith('r'):
            note = '  ;indirect'
            sends.append(dict(address=hex(addr), target='indirect-register'))
        annotated.append(f'{addr:08x}: {word(addr):08x} {text}{note}')
        # keep register-slot map only while live; simple model: overwrite ok
    lines = list(annotated)
    for s, e in pools:
        for addr in range(s, e, 4):
            # If a code instruction loads this literal and the very next
            # instruction recomputes it as (addr+12 + word), the word is a
            # GOT anchor (PIC base) constant, not a slot offset.
            recompute = None
            for c in sorted(code):
                i = code[c]
                if i.mnemonic not in ('ldr', 'ldrb', 'ldrsb', 'ldrd') or '[pc, #' not in i.op_str:
                    continue
                try:
                    imm = int(i.op_str.rsplit('#', 1)[1].rstrip(']'), 0)
                except ValueError:
                    continue
                if (c + 8 + imm) & 0xffffffff != addr:
                    continue
                j = code.get(c + 4)
                regs = [t.strip() for t in j.op_str.split(',')] if j and j.mnemonic == 'add' else []
                want = i.op_str.split(',')[0].strip()
                if len(regs) == 3 and regs[1] == 'pc' and regs[0] == want and regs[2] == want:
                    recompute = (c + 12 + word(addr)) & 0xffffffff
                    break
            if recompute is not None:
                info = {'kind': 'got-anchor-recompute', 'slot': hex(recompute),
                        'matches_pic_base': recompute == PIC}
            else:
                slot = (PIC + word(addr)) & 0xffffffff
                try:
                    info = resolve_slot(slot)
                except ValueError:
                    info = {'kind': 'unreadable'}
            lines.append(f'{addr:08x}: {word(addr):08x} .word  ;' + json.dumps(info, sort_keys=True))

    lines_sorted = sorted(lines, key=lambda s: int(s[:8], 16))
    lines_sorted = [
        f'# Blockhead -[pickupFreeblockIfPossible:inTile:intentional:]',
        f'# implementation: {START:#x}',
        f'# region manifest: currency-split {CURRENCY_START:#x}..{CURRENCY_END:#x}'
        ' plus tail; supersedes the coarse POOLS list in recover_inventory_pickup.py',
        '# for the currency region: CFG-based code/data split with pc-relative',
        '# pool words forced to data (capstone decodes pool words as instructions).',
    ] + lines_sorted
    result = dict(
        schema=1, elf_sha256=SHA,
        method='Blockhead -[pickupFreeblockIfPossible:inTile:intentional:]',
        implementation='0x%08x' % START,
        region=dict(start=hex(CURRENCY_START), end=hex(CURRENCY_END)),
        pic_base=hex(PIC),
        cfg=dict(instruction_count=len(code), data_word_count=len(data),
                 pools=[(hex(s), hex(e)) for s, e in pools]),
        edges=[dict(src=hex(s), dst=(hex(d) if d else None), kind=k) for s, d, k in sorted(edges)],
        calls=sends, stubs=stubs,
        anchors={'type-money-cmp': '0x12a at 0xc6296c/0xc629a8',
                 'loop1-denomination-movw-0x104': '0xc62a38',
                 'loop2-denomination-movw-0xa7': '0xc62c2c',
                 'loop3-denomination-movw-0xa6': '0xc62e0c',
                 'magic-10000-smmul': '0xc62fc4 (movw 0x8bad/movt 0x68db, smmul, asr #12, mls #0x2710)',
                 'hundred-movw': '0xc62dbc (100 literal passed near idiv stub call)'},
        runtime_verified=False, integrated_into_game=False,
        semantics_status='manifest + hand review; behaviour contract recorded separately')
    out_json = json.dumps(result, indent=2) + '\n'
    out_txt = '\n'.join(lines_sorted) + '\n'
    out = ROOT / 'reconstruction/reverse-v3/native'
    for name, data_ in [('inventory_pickup_currency.json', out_json),
                        ('disasm_inventory_pickup_currency.txt', out_txt)]:
        t = out / name
        if a.check:
            assert t.read_text() == data_, 'stale ' + name
        else:
            t.write_text(data_)
    print(json.dumps(dict(instructions=len(code), data_words=len(data),
                          pools=len(pools), calls=len(sends), stubs=stubs)))


ROOT = Path(__file__).resolve().parents[1]
if __name__ == '__main__':
    main()
