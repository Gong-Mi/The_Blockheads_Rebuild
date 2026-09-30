#!/usr/bin/env python3
"""Cross-check the linear GameView -[init] dispatch facts against a join-merge
bounded-CFG replay of the same pinned function.

Both passes share the transfer semantics of tools/recover_gameview_init.py:
  * linear pass  = path order as laid out (frame slots make spill/reload
    concrete, so loop-carried selector reloads survive).
  * CFG pass     = worklist; every program point keeps the intersection of
    facts over all paths reaching it (loop-header joins discard anything not
    agreed by all incoming paths).

Findings encoded by this tool (2026-09-14, ELF 733d8210…b94c7):
  CFG-proven selector sites are a strict SUBSET of linear ones (15 of 27),
  with ZERO conflicts and ZERO additions. Two consequences:
    1. For those 15 sites the linear layout-order reasoning is independently
       re-derivable without path-order assumptions -> strengthened evidence.
    2. The CFG join cannot beat the linear model here: spill/reload chains
       through loop headers (selectors preloaded before a loop, consumed
       inside) are exactly what all-path intersection removes. The remaining
       12 linear-only sites keep their linear-level confidence.
Any future disagreement (CFG fact not present in linear output) fails hard.

Local acceptance layer: requires the pinned original ELF; not run in CI.
"""
import argparse
import json
import re
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import capstone
from trace_objc_dispatch import ELFMemory
import recover_gameview_init as linear

START, END = linear.START, linear.END


def cfg_selector_sites(elf_path: Path):
    """Re-run the shared transfer rules on a worklist with all-path joins.

    Only selector facts are compared; the linear tool owns every other output.
    """
    memory = ELFMemory(elf_path)
    base = linear.EXPECTED_BASE
    ranges = linear.section_ranges(elf_path)
    selrefs = ranges['__objc_selrefs']
    # Rebuild the same classifiers against this memory instance.
    import types
    helper = types.SimpleNamespace()
    # Cheap route: reuse the linear module's own simulation by monkey-reading
    # its compiled regexes is fragile; instead run its recover() and extract
    # per-site r1 knowledge separately via an identical step function here.
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    off0 = memory.offset(START, 4)
    decoded = {}
    for a0 in range(START, END, 4):
        raw = memory.data[off0 + (a0 - START): off0 + (a0 - START) + 4]
        got = list(md.disasm(raw, a0))
        if got:
            decoded[a0] = (got[0].mnemonic + ' ' + got[0].op_str).strip().replace('#', '')
    addresses = sorted(decoded)
    idx = {a: i for i, a in enumerate(addresses)}
    R, NUM = linear.R, linear.NUM
    reg, num, signed = linear.reg, linear.num, linear.signed

    symval = linear.dynamic_symbol_map(elf_path)

    def cstr(addr):
        if addr is None:
            return None
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = memory.data.find(b'\0', off, off + 512)
        return memory.data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    cfstr, clsrefs, ivars, methnames = (ranges['__cfstring'], ranges['__objc_classrefs'],
                                        ranges['__objc_ivar'], ranges['__objc_methname'])

    def pic_sum(x, y):
        if y == base: return (base + signed(x)) & 0xffffffff
        if x == base: return (base + signed(y)) & 0xffffffff
        if signed(x) < 0 <= y and 0x0e00000 <= y <= 0x1200000:
            return (y + signed(x)) & 0xffffffff
        if signed(y) < 0 <= x and 0x0e00000 <= x <= 0x1200000:
            return (x + signed(y)) & 0xffffffff
        return (x + y) & 0xffffffff

    def classify(state, dest, slot):
        slot &= 0xffffffff
        if slot in memory.imports:
            state[dest] = ('import', memory.imports[slot]); return
        if selrefs[0] <= slot < selrefs[1]:
            w = memory.word(slot)
            if w is not None: state[dest] = ('sel', w, slot)
            else: state.pop(dest, None)
            return
        if cfstr[0] <= slot < cfstr[1]:
            state[dest] = ('cfstr', slot); return
        if clsrefs[0] <= slot < clsrefs[1]:
            state[dest] = ('clsref', slot, symval.get(memory.word(slot), '')); return
        w = memory.word(slot) if slot not in memory.unsupported_relocations else None
        if w is None:
            state.pop(dest, None); return
        if ivars[0] <= w < ivars[1]:
            state[dest] = ('ivarslot', slot, w, symval.get(slot, '')); return
        if methnames[0] <= w < methnames[1]:
            state[dest] = ('cstr', w); return
        state[dest] = w

    P = {name: re.compile(pattern) for name, pattern in {
        'LDR_LIT': r'^ldr\s+(%s),\s+\[pc,\s+%s\]$',
        'ADD_PC': r'^add\s+(%s),\s+pc,\s+(%s)$',
        'ADD_RR': r'^add\s+(%s),\s+(%s),\s+(%s)$',
        'ADDSUB_I': r'^(add|sub)(?:\.w)?\s+(%s),\s+(%s),\s+%s$',
        'MOV': r'^mov(?:\.w)?\s+(%s),\s+(%s)$',
        'MOVW': r'^movw\s+(%s),\s+(0[xX][0-9a-fA-F]+|\d+)$',
        'MOVT': r'^movt\s+(%s),\s+(0[xX][0-9a-fA-F]+|\d+)$',
        'LDR_OFS': r'^ldr(?:\.w)?\s+(%s),\s+\[(%s),\s+%s\]$',
        'LDR_OO': r'^ldr(?:\.w)?\s+(%s),\s+\[(%s),\s+(%s)\]$',
        'LDR_P': r'^ldr(?:\.w)?\s+(%s),\s+\[(%s)\]$',
        'STR_P': r'^str(?:\.w)?\s+(%s),\s+\[(%s)\]$',
        'STR_OFS': r'^str(?:\.w)?\s+(%s),\s+\[(%s),\s+%s\]$',
        'STR_OO': r'^str(?:\.w)?\s+(%s),\s+\[(%s),\s+(%s)\]$',
        'BLR': r'^blx\s+(%s)$',
    }.items()}
    def two(): return P['LDR_LIT'].pattern % (R, NUM)
    P['LDR_LIT'] = re.compile(P['LDR_LIT'].pattern % (R, NUM))
    P['ADD_PC'] = re.compile(P['ADD_PC'].pattern % (R, R))
    P['ADD_RR'] = re.compile(P['ADD_RR'].pattern % (R, R, R))
    P['ADDSUB_I'] = re.compile(P['ADDSUB_I'].pattern % (R, R, NUM))
    P['MOV'] = re.compile(P['MOV'].pattern % (R, R))
    P['MOVW'] = re.compile(P['MOVW'].pattern % R)
    P['MOVT'] = re.compile(P['MOVT'].pattern % R)
    P['LDR_OFS'] = re.compile(P['LDR_OFS'].pattern % (R, R, NUM))
    P['LDR_OO'] = re.compile(P['LDR_OO'].pattern % (R, R, R))
    P['LDR_P'] = re.compile(P['LDR_P'].pattern % (R, R))
    P['STR_P'] = re.compile(P['STR_P'].pattern % (R, R))
    P['STR_OFS'] = re.compile(P['STR_OFS'].pattern % (R, R, NUM))
    P['STR_OO'] = re.compile(P['STR_OO'].pattern % (R, R, R))
    P['BLR'] = re.compile(P['BLR'].pattern % R)

    BRANCHES = {'b' + c for c in ('eq','ne','cs','hs','cc','lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le')}

    def step(st, a, full):
        r, stack = st['r'], st['stack']
        m0 = full.split(None, 1)[0]

        def fall():
            i = idx[a]
            return [addresses[i + 1]] if i + 1 < len(addresses) else []

        if m0 == 'push':
            return fall()
        if m0 == 'pop':
            names = re.findall(r'r\d+|ip|sl|fp|lr|pc', full)
            if 'pc' in names:
                return []
            if 'r11' in names or 'fp' in names:
                stack.clear()
            for name in names:
                r.pop(reg(name), None)
            return fall()
        m = P['LDR_LIT'].match(full)
        if m:
            dest = reg(m[1]); lit = (a + 8 + num(m[2])) & 0xffffffff
            w = memory.word(lit)
            if w is None: r.pop(dest, None)
            else: r[dest] = w
            return fall()
        m = P['ADD_PC'].match(full)
        if m:
            dest, s2 = reg(m[1]), reg(m[2])
            v = r.get(s2)
            if isinstance(v, int): r[dest] = (a + 8 + v) & 0xffffffff
            else: r.pop(dest, None)
            return fall()
        m = P['ADD_RR'].match(full)
        if m:
            dest, x, y = reg(m[1]), reg(m[2]), reg(m[3])
            xv, yv = r.get(x), r.get(y)
            if isinstance(xv, int) and isinstance(yv, int): r[dest] = pic_sum(xv, yv)
            else: r.pop(dest, None)
            return fall()
        m = P['ADDSUB_I'].match(full)
        if m:
            op, dest, s2, off = m[1], reg(m[2]), reg(m[3]), num(m[4])
            if dest == 'r11' and s2 == 'r13' and op == 'add':
                st['sp_to_fp'] = off; return fall()
            if dest == 'r13' and s2 == 'r13' and st['sp_to_fp'] is not None:
                st['sp_to_fp'] += off if op == 'add' else -off
                return fall()
            if dest == 'r11' or s2 == 'r11':
                r.pop(dest, None); stack.clear(); return fall()
            if op == 'add' and s2 == 'r15':
                r[dest] = (a + 8 + off) & 0xffffffff; return fall()
            v = r.get(s2)
            if isinstance(v, int):
                r[dest] = (v + off if op == 'add' else v - off) & 0xffffffff
            else: r.pop(dest, None)
            return fall()
        m = P['MOV'].match(full)
        if m:
            dest, s2 = reg(m[1]), reg(m[2])
            if 'r11' in (dest, s2): r.pop(dest, None)
            elif s2 in r: r[dest] = r[s2]
            else: r.pop(dest, None)
            return fall()
        m = P['MOVW'].match(full)
        if m: r[reg(m[1])] = num(m[2]); return fall()
        m = P['MOVT'].match(full)
        if m:
            dest = reg(m[1]); v = r.get(dest)
            if isinstance(v, int): r[dest] = (v & 0xffff) | (num(m[2]) << 16)
            else: r.pop(dest, None)
            return fall()
        m = P['LDR_OFS'].match(full)
        if m:
            dest, b, off = reg(m[1]), reg(m[2]), num(m[3])
            if b == 'r13' and st['sp_to_fp'] is not None:
                off, b = off - st['sp_to_fp'], 'r11'
            if b == 'r11':
                v = stack.get(off)
                if v is not None: r[dest] = v
                else: r.pop(dest, None)
                return fall()
            bv = r.get(b)
            if isinstance(bv, int): classify(r, dest, (bv + off) & 0xffffffff)
            else: r.pop(dest, None)
            return fall()
        m = P['LDR_OO'].match(full)
        if m:
            dest, b, o = reg(m[1]), reg(m[2]), reg(m[3])
            bv, ov = r.get(b), r.get(o)
            if isinstance(bv, int) and isinstance(ov, int):
                classify(r, dest, pic_sum(bv, ov))
            else: r.pop(dest, None)
            return fall()
        m = P['LDR_P'].match(full)
        if m:
            dest, b = reg(m[1]), reg(m[2])
            if b == 'r13' and st['sp_to_fp'] is not None:
                v = stack.get(-st['sp_to_fp'])
                if v is not None: r[dest] = v
                else: r.pop(dest, None)
                return fall()
            bv = r.get(b)
            if isinstance(bv, int): classify(r, dest, bv)
            else: r.pop(dest, None)
            return fall()
        m = P['STR_P'].match(full)
        if m:
            sreg, b = reg(m[1]), reg(m[2])
            if b == 'r13' and st['sp_to_fp'] is not None:
                stack[-st['sp_to_fp']] = r.get(sreg)
            elif b == 'r11':
                stack[0] = r.get(sreg)
            return fall()
        m = P['STR_OFS'].match(full)
        if m:
            sreg, b, off = reg(m[1]), reg(m[2]), num(m[3])
            if b == 'r13' and st['sp_to_fp'] is not None:
                stack[off - st['sp_to_fp']] = r.get(sreg)
            elif b == 'r11':
                stack[off] = r.get(sreg)
            return fall()
        m = P['STR_OO'].match(full)
        if m:
            return fall()
        m = P['BLR'].match(full)
        if m:
            t = reg(m[1])
            st['calls'] = st.get('calls', {})
            st['calls'][a] = (r.get(t), r.get('r1'))
            for c in ('r0', 'r1', 'r2', 'r3', 'ip'): r.pop(c, None)
            return fall()
        m = re.match(r'^bl\s+(\S+)$', full)
        if m:
            for c in ('r0', 'r1', 'r2', 'r3', 'ip'): r.pop(c, None)
            return fall()
        if m0 == 'bx' and full.split()[1] == 'lr':
            return []
        if m0 == 'b' or m0 in BRANCHES:
            successors = []
            mb = re.match(r'^b\.?\w*\s+(0[xX][0-9a-fA-F]+|\d+)$', full)
            if mb and (num(mb[1]) & 0xffffffff) in idx:
                successors.append(num(mb[1]) & 0xffffffff)
            if m0 != 'b':
                successors.extend(fall())
            return successors
        if m0.startswith('v') or m0 in ('vmrs', 'vmov'):
            return fall()
        dm = re.match(r'^(' + R + r')(?:,|\[)', full.split(None, 1)[1] if ' ' in full else '')
        if dm:
            r.pop(reg(dm[1]), None)
        return fall()

    states = {START: {'r': {'r2': base}, 'stack': {}, 'sp_to_fp': None}}
    queue = deque([START])
    budget = 400000
    while queue and budget > 0:
        a = queue.popleft()
        budget -= 1
        st = states[a]
        for s_addr in step(st, a, decoded[a]):
            incoming = {'r': {k: v for k, v in st['r'].items() if k != 'calls'},
                        'stack': dict(st['stack']), 'sp_to_fp': st['sp_to_fp']}
            old = states.get(s_addr)
            if old is None:
                states[s_addr] = {'r': dict(incoming['r']), 'stack': dict(incoming['stack']),
                                  'sp_to_fp': incoming['sp_to_fp']}
                queue.append(s_addr)
            else:
                keep_r = {k: v for k, v in old['r'].items()
                          if k in incoming['r'] and incoming['r'][k] == v}
                keep_r['r2'] = base
                keep_s = {k: v for k, v in old['stack'].items()
                          if k in incoming['stack'] and incoming['stack'][k] == v}
                keep_sp = (old['sp_to_fp'] if old['sp_to_fp'] == incoming['sp_to_fp'] else None)
                if (keep_r != old['r'] or keep_s != old['stack']
                        or keep_sp != old['sp_to_fp']):
                    old['r'], old['stack'], old['sp_to_fp'] = keep_r, keep_s, keep_sp
                    queue.append(s_addr)
    # Per-site selector facts: only visits whose join state still carries the
    # value count. blx stored targets/r1 inside the state at the call point.
    result = {}
    for st_addr, st in states.items():
        for call, (target, sel) in (st.get('calls') or {}).items():
            if isinstance(sel, tuple) and sel[0] == 'sel':
                name = cstr(sel[1])
                if name:
                    result[f'0x{call:08x}'] = name
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--json', type=Path)
    args = parser.parse_args()

    linear_report = linear.recover(args.elf)
    linear_sel = {row['call']: row['selector']['name']
                  for row in linear_report['calls']
                  if row['selector'].get('kind') == 'selector'}
    cfg_sel = cfg_selector_sites(args.elf)

    conflicts = {k: (linear_sel.get(k), v) for k, v in cfg_sel.items()
                 if k in linear_sel and linear_sel[k] != v}
    additions = {k: v for k, v in cfg_sel.items() if k not in linear_sel}
    confirmed = sorted(set(cfg_sel) & set(linear_sel))
    if conflicts:
        raise SystemExit(f'pass disagreement, refusing to report: {conflicts}')
    if additions:
        raise SystemExit(f'CFG produced facts absent from linear pass; '
                         f'requires review before promotion: {additions}')

    summary = {
        'linear_selector_sites': len(linear_sel),
        'cfg_confirmed_sites': len(confirmed),
        'cfg_subset': True,
        'conflicts': conflicts,
        'additions': additions,
        'confirmed_calls': confirmed,
    }
    payload = json.dumps(summary, indent=2, sort_keys=True) + '\n'
    if args.json:
        args.json.write_text(payload)
    print(payload)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
