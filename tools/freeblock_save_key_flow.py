#!/usr/bin/env python3
"""Bounded forward trace of FreeBlock -[getSaveDict] pairing blx sites to selector/key.

Semantics:
- literal-cell loads are tagged CELL(celladdr); adding the PIC base resolves them
  to concrete addresses exactly like the checked-in recovery scripts do.
- stack stores keep values in a simulated stack dict; loads check the stack first.
- any value the trace cannot derive stays None; no site is promoted by proximity.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from trace_objc_dispatch import ELFMemory

START, CODE_END = 0x629804, 0x62A410
CELL_LO, CELL_HI = 0x62A414, 0x62A4B8


def sgn(v):
    return v - (1 << 32) if v & 0x80000000 else v


def main(elf_path):
    m = ELFMemory(Path(elf_path))

    def word(a):
        v = m.word(a)
        return None if v is None else int(v)

    def cstr(a):
        if not isinstance(a, int):
            return None
        off = m.offset(a, 1)
        if off is None:
            return None
        e = m.data.find(b'\0', off, off + 96)
        if e < 0:
            return None
        try:
            s = m.data[off:e].decode('ascii')
        except UnicodeDecodeError:
            return None
        return s if len(s) > 1 and s.isprintable() else None

    def key_text(obj):
        # classic CFString constant: data pointer at +8
        if not isinstance(obj, int):
            return None
        return cstr(word(obj + 8))

    regs = {}   # name -> ('cell', addr) | ('val', int) | None
    stack = {}
    regs['sp'] = ('val', 0)

    def val(name):
        t = regs.get(name)
        if t and t[0] == 'val':
            return t[1]
        return None

    def setv(name, v):
        regs[name] = (None if v is None else ('val', v & 0xffffffff))

    def setcell(name, a):
        regs[name] = ('cell', a & 0xffffffff)

    def raw(name):
        t = regs.get(name)
        if not t:
            return None
        if t[0] == 'cell':
            v = word(t[1])
            return None if v is None else sgn(int(v))
        return t[1]

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    blob = m.data[m.offset(START, CODE_END - START):]
    rows = []
    for ins in md.disasm(blob, START):
        mn, ops = ins.mnemonic, ins.op_str
        a = ins.address
        if mn.startswith('bl'):
            sel_name = None
            r1 = val('r1')
            if r1 is not None:
                sel_name = m.selectors.get(r1)
            key = key_text(val('r3'))
            # direct bl to an import thunk resolves the dispatch, not a selector
            mn_note = None
            if mn == 'bl':
                tgt = ops.lstrip('#')
                try:
                    mn_note = m.imports.get(int(tgt, 0) if ops.startswith('#') else None)
                except (ValueError, TypeError):
                    mn_note = None
            treg = regs.get(ops.strip())
            if treg and treg[0] == 'import':
                mn_note = treg[1]
            rows.append({'site': f'0x{a:08x}', 'mn': mn, 'ops': ops,
                         'r0': val('r0'), 'r1_sel': sel_name, 'r3_key': key,
                         'dispatch': mn_note or ('objc_msgSend' if mn == 'blx' else None)})
            for c in ('r0', 'r1', 'r2', 'r3', 'r12'):
                regs[c] = None
            continue
        parts = [p.strip() for p in ops.split(',')]
        if mn == 'ldr':
            dst = parts[0]
            rest = ops[ops.index('[') + 1:ops.rindex(']')]
            rp = [p.strip() for p in rest.split(',')]
            if rp[0] == 'pc':
                imm = int(rp[1][1:], 0) if len(rp) > 1 else 0
                setcell(dst, (a + 8 + imm) & 0xffffffff)
                continue
            addr = None
            if len(rp) == 1:
                addr = raw(rp[0]) if regs.get(rp[0]) and regs[rp[0]][0] == 'val' else None
            else:
                b = rp[0]
                bcell = regs.get(b)
                if bcell and bcell[0] == 'cell':
                    other = raw(rp[1]) if regs.get(rp[1]) and regs[rp[1]][0] == 'val' else None
                    if other is not None:
                        addr = (other + bcell[1] and 0xffffffff) if False else None
                        # cell + base: address = (base + sgn(word(cell)))
                        base = val(rp[1])
                        wv = word(bcell[1])
                        if base is not None and wv is not None:
                            addr = (base + sgn(wv)) & 0xffffffff
                elif bcell and bcell[0] == 'val':
                    off = int(rp[1][1:], 0) if rp[1].startswith('#') else val(rp[1])
                    if off is not None:
                        addr = (bcell[1] + sgn(off)) & 0xffffffff
            if addr is None:
                regs[dst] = None
                continue
            if addr in stack:
                v = stack[addr]
                regs[dst] = v if v is not None else None
            else:
                w = word(addr)
                imp = m.imports.get(addr)
                if imp:
                    regs[dst] = ('import', imp)
                else:
                    setv(dst, w)
            continue
        if mn in ('str', 'strb'):
            src = parts[0]
            rest = ops[ops.index('[') + 1:ops.rindex(']')]
            rp = [p.strip() for p in rest.split(',')]
            b = regs.get(rp[0])
            addr = None
            if b and b[0] == 'val':
                off = int(rp[1][1:], 0) if len(rp) > 1 and rp[1].startswith('#') else (val(rp[1]) if len(rp) > 1 else 0)
                if off is not None:
                    addr = (b[1] + sgn(off)) & 0xffffffff
            if addr is not None:
                stack[addr] = regs.get(src)
            continue
        if mn == 'add':
            dst = parts[0]
            if len(parts) == 3 and 'pc' in (parts[1], parts[2]):
                other = parts[1] if parts[2] == 'pc' else parts[2]
                v = raw(other)
                if v is not None:
                    setv(dst, (a + 8) + v)
                else:
                    regs[dst] = None
                continue
            if len(parts) == 2:
                v = regs.get(parts[1])
                regs[dst] = v if v and v[0] == 'val' else None
                continue
            b = parts[1]
            off_src = parts[2]
            t = regs.get(b)
            off = None
            st = regs.get(off_src)
            if off_src.startswith('#'):
                off = int(off_src[1:], 0)
            elif st and st[0] == 'val':
                off = st[1]
            elif st and st[0] == 'cell':
                # add rD, rM, ip where ip is a literal cell and rM is the PIC
                # base: the slot address is base + cell address (word is read
                # later by the ldr step); emulate by computing cell slot addr.
                w = word(st[1])
                b2 = val(b)
                if w is not None and b2 is not None:
                    setv(dst, (b2 + sgn(w)) & 0xffffffff)
                    continue
                off = None
            elif regs.get(off_src) is None and off_src.startswith('r'):
                off = None
            if t and t[0] == 'cell' and off is not None:
                w = word(t[1])
                if w is not None:
                    setv(dst, (off + sgn(w)) & 0xffffffff)
                else:
                    regs[dst] = None
                continue
            if t and t[0] == 'val' and off is not None:
                setv(dst, t[1] + off)
            else:
                regs[dst] = None
            continue
        if mn in ('sub', 'rsb'):
            dst = parts[0]
            if len(parts) == 3:
                b = val(parts[1])
                o = parts[2]
                off = int(o[1:], 0) if o.startswith('#') else val(o)
                if b is not None and off is not None:
                    setv(dst, (b - off) if mn == 'sub' else (off - b))
                    continue
            regs[dst] = None
            continue
        if mn == 'mov' and len(parts) == 2:
            regs[parts[0]] = regs.get(parts[1])
            continue
        if mn in ('vmov', 'vldr', 'vstr', 'vstrd', 'vldr2'):
            continue
        if mn == 'sxtb':
            regs[parts[0]] = None
            continue
        if parts and parts[0].startswith('r') or (parts and parts[0] in ('ip', 'lr', 'fp', 'sl')):
            regs[parts[0]] = None

    resolved = [r for r in rows if r['r1_sel'] or r['r3_key']]
    print(json.dumps({'total_blx_bl_sites': len(rows), 'resolved_sites': resolved}, indent=1))


if __name__ == '__main__':
    main(sys.argv[1])
