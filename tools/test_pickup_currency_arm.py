#!/usr/bin/env python3
"""Pinned original ARM currency-split region vs recovered C++ O0/O2.

Executes the real bytes 0xc628f8.. of pickupFreeblockIfPossible:inTile:
intentional: under Unicorn until one of the region's three exits:
  0xc63340 non-money tail (second itemType != 0x12a)
  0xc62ff0 residual>0 tail (lazily resolved .bss ivar slots, NOT recovered)
  0xc630a8 zero-residual tail (same boundary)
Only objc_msgSend (import slot + PLT stub GOT), __aeabi_idiv and __modsi3
are hooked; field re-reads, loop counters, the *100 cascade and the
/10000 smmul magic run as original instructions. Compares the FULL message
sequence (selector + receiver tag + typed argument) AND the frame loop
counters (plus K/R) at the stop edge. Synthetic runtime only: no
Foundation, no original app, no device. No claim beyond the stop edges.
"""
import argparse, hashlib, json, struct, subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_SP, UC_ARM_REG_FP, UC_ARM_REG_LR, UC_ARM_REG_PC)

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
ENTRY = 0xc628f8
STOPS = {0xc63340: 'nonmoney', 0xc62ff0: 'residual', 0xc630a8: 'zerotail'}
DENOMS = (0x104, 0xa7, 0xa6)  # platinum / gold / copper (server ItemType)


def s32(v):
    return struct.unpack('<i', struct.pack('<I', v & 0xffffffff))[0]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--output-dir', type=Path, required=True)
    a = p.parse_args()
    assert hashlib.sha256(a.elf.read_bytes()).hexdigest() == SHA
    a.output_dir.mkdir(parents=True, exist_ok=True)
    with a.elf.open('rb') as f:
        elf = ELFFile(f)
        loads = [(s['p_vaddr'], s['p_memsz'], s.data())
                 for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    pages = set()
    for base, size, _ in loads:
        pages.update(range(base & ~4095, (base + size + 4095) & ~4095, 4096))
    for page in sorted(pages):
        u.mem_map(page, 4096)
    for base, _, data in loads:
        u.mem_write(base, data)

    def word(addr):
        return struct.unpack('<I', bytes(u.mem_read(addr, 4)))[0]

    def put(addr, value):
        u.mem_write(addr, struct.pack('<I', value & 0xffffffff))

    def gstr(addr):
        raw = bytes(u.mem_read(addr, 256))
        return raw.split(b'\0')[0].decode(errors='replace')

    pic = (0xc61c14 + 8 + word(0xc62bb8)) & 0xffffffff
    heap, stack, sentinel = 0x60000000, 0x70000000, 0x71000000
    u.mem_map(heap, 0x20000)
    u.mem_map(stack, 0x40000)
    u.mem_map(sentinel, 0x3000)
    send, idiv_x, mod_x = sentinel + 0x1000, sentinel + 0x1100, sentinel + 0x1200
    for addr in (send, idiv_x, mod_x):
        u.mem_write(addr, bytes.fromhex('1eff2fe1'))  # bx lr; hook retires
    put(0x105b7a0, send)    # PIC import slot (literal 0xc63808)
    put(0x105fb18, send)    # PLT stub 0x1c281c GOT
    put(0x106001c, idiv_x)  # __aeabi_idiv GOT (stub 0x1c3728)
    put(0x105fdc4, mod_x)   # __modsi3 GOT (stub 0x1c3020)
    klass = 0xe91ca0          # OBJC_CLASS_$_InventoryItem (slot word at 0xc63850)

    self_, freeblock, item = heap + 0x1000, heap, heap + 0x8000
    sp = stack + 0x8000
    fp = sp + 0x500  # keep [fp-0x248..] clear of the method's stack temps
    put(fp - 0x248, pic)
    put(fp - 0x1a0, self_)      # self slot
    put(fp - 0x1a8, freeblock)  # resolved freeblock slot
    put(fp - 0x1ac, heap + 0x1800)  # tile argument (unused in this region)

    tags = {self_: 's', freeblock: 'f', item: 'i', klass: 'I'}
    ctx, trace = {}, []

    def ret(val):
        u.reg_write(UC_ARM_REG_R0, val & 0xffffffff)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR) & ~1)

    def code(uc, address, size, data):
        if address in STOPS:
            ctx['stop'] = STOPS[address]
            uc.emu_stop()
            return
        if address == send:
            sel = gstr(uc.reg_read(UC_ARM_REG_R1))
            recv = uc.reg_read(UC_ARM_REG_R0)
            tag = tags.get(recv, '?')
            r2 = uc.reg_read(UC_ARM_REG_R2)
            if sel == 'itemType':
                assert tag == 'f', sel
                trace.append('itemType@f')
                ret(ctx['type'])
            elif sel == 'setNeedsRemoved:':
                assert tag == 'f', sel
                trace.append('setNeedsRemoved@f=%d' % s32(r2))
                ret(0)
            elif sel in ('dataA', 'dataB'):
                assert tag == 'f', sel
                trace.append(sel + '@f')
                ret(ctx['dataA'] if sel == 'dataA' else ctx['dataB'])
            elif sel.startswith('canPickUp'):
                assert tag == 's', sel
                assert r2 in DENOMS, hex(r2)
                v = ctx['gates'][min(ctx['i'], len(ctx['gates']) - 1)]
                ctx['i'] += 1
                trace.append('gate@%d@s' % r2)
                ret(v)
            elif sel == 'alloc':
                assert tag == 'I', sel
                trace.append('alloc@I')
                ret(item)
            elif sel.startswith('initWithType'):
                assert tag == 'i' and r2 in DENOMS, sel
                trace.append('init@%d@i' % r2)
                ret(item)
            elif sel == 'autorelease':
                assert tag == 'i', sel
                trace.append('autorel@i')
                ret(item)
            elif sel == 'addItemToInventory:flash:':
                assert tag == 's', sel
                trace.append('add@s')
                ret(7)
            else:
                raise AssertionError(sel)
        elif address == idiv_x:
            x, y = s32(uc.reg_read(UC_ARM_REG_R0)), s32(uc.reg_read(UC_ARM_REG_R1))
            q = abs(x) // abs(y) * (1 if (x < 0) == (y < 0) else -1)
            ret(q)
        elif address == mod_x:
            x, y = s32(uc.reg_read(UC_ARM_REG_R0)), s32(uc.reg_read(UC_ARM_REG_R1))
            q = abs(x) // abs(y) * (1 if (x < 0) == (y < 0) else -1)
            ret(x - q * y)

    u.hook_add(UC_HOOK_CODE, code, begin=0xc62000, end=0xc64000)
    for lo in (send, idiv_x, mod_x):
        u.hook_add(UC_HOOK_CODE, code, begin=lo, end=lo + 4)

    cases = []
    for type_ in (0x12a, 0xb, 20):
        for a_ in (0, 1, 2, 0x10005):
            for b_ in (0, 7, 100, 123):
                for gates in ([1], [2], [0], [1, 2], [1, 1, 0], [1, 0, 1]):
                    cases.append((type_, a_, b_, gates))
    arm_lines = []
    for type_, a_, b_, gates in cases:
        ctx.update(type=type_, dataA=a_, dataB=b_, gates=gates, i=0, stop=None)
        trace.clear()
        for off in (0x208, 0x218, 0x224, 0x230, 0x234):
            put(fp - off, 0xdead)  # poison; region must write before stop edge
        for reg, value in [(UC_ARM_REG_R0, self_), (UC_ARM_REG_SP, sp),
                           (UC_ARM_REG_FP, fp), (UC_ARM_REG_LR, sentinel)]:
            u.reg_write(reg, value)
        u.emu_start(ENTRY, sentinel, count=2_000_000)
        assert ctx['stop'], 'region exited without hitting a stop edge'
        line = ' '.join(trace) + ' | stop=' + ctx['stop']
        if ctx['stop'] != 'nonmoney':
            counters = [word(fp - 0x208), word(fp - 0x218), word(fp - 0x224)]
            assert all(c != 0xdead for c in counters), counters
            line += ' P=%d G=%d C=%d' % tuple(counters)
            if ctx['stop'] == 'residual':
                assert word(fp - 0x230) != 0xdead and word(fp - 0x234) != 0xdead
                line += ' K=%d R=%d' % (word(fp - 0x230), word(fp - 0x234))
        arm_lines.append(line)

    root = Path(__file__).resolve().parents[1]
    blob = ''.join('%d %d %d %s\n' % (t, x, y, ' '.join(map(str, g)))
                   for t, x, y, g in cases)

    def build(exe, source):
        subprocess.run(['clang++', '-std=c++17', '-UNDEBUG', '-I',
                        str(root / 'reconstruction/recovered'),
                        str(root / 'tools/pickup_currency_probe.cpp'),
                        source, '-o', str(exe)], check=True)
        return subprocess.run([str(exe)], input=blob, text=True,
                              capture_output=True, check=True).stdout.splitlines()

    reports = []
    for opt in ('O0', 'O2'):
        exe = a.output_dir / ('currency-' + opt)
        # -O flag is inside clang invocation; patch build to carry opt
        subprocess.run(['clang++', '-std=c++17', '-' + opt, '-UNDEBUG', '-I',
                        str(root / 'reconstruction/recovered'),
                        str(root / 'tools/pickup_currency_probe.cpp'),
                        str(root / 'reconstruction/recovered/inventory_pickup_currency.cpp'),
                        '-o', str(exe)], check=True)
        cpp = subprocess.run([str(exe)], input=blob, text=True,
                             capture_output=True, check=True).stdout.splitlines()
        assert len(cpp) == len(arm_lines), (len(cpp), len(arm_lines))
        mism = [dict(case=list(cases[i]), arm=x, cpp=y)
                for i, (x, y) in enumerate(zip(arm_lines, cpp)) if x != y]
        reports.append(dict(optimization=opt, cases=len(cases),
                            mismatch_count=len(mism), mismatches=mism[:6]))
        if opt == 'O2':
            assert not mism, json.dumps(mism[:4], indent=2)

    src = (root / 'reconstruction/recovered/inventory_pickup_currency.cpp').read_text()
    negatives = []
    for name, old, new in [
        ('limit3-base-cascade-to-raw', '(limit2 - out.gold) * 100 + b % 100',
         '(a - out.platinum) * 100 + b % 100'),
        ('skip-zeroxb-setneedsremoved', 'r.setNeedsRemoved(freeblock, 1);\n    }',
         ' }\n    if (false) r.setNeedsRemoved(freeblock, 1);'),
        ('drop-uxth-dataA', 'const std::int32_t a = uxth(r.dataA(freeblock));',
         'const std::int32_t a = r.dataA(freeblock);'),
        ('gate-nonstrict', 'if (r.sendCanPickUp(self, denom) != 1) return;',
         'if (r.sendCanPickUp(self, denom) < 1) return;'),
    ]:
        assert src.count(old) == 1, name
        altered = a.output_dir / ('neg-' + name + '.cpp')
        altered.write_text(src.replace(old, new))
        lines = build(a.output_dir / ('neg-' + name), str(altered))
        bad = sum(1 for x, y in zip(arm_lines, lines) if x != y)
        negatives.append(dict(control=name, mismatches=bad))
        assert bad > 0, 'negative control not detected: ' + name

    result = dict(oracle='pinned ARM 0xc628f8..stop edges vs C++ probe',
                  elf_sha256=SHA, cases=len(cases), reports=reports,
                  negative_controls=negatives,
                  runtime_verified_original_app=False,
                  boundary='region only; tail slots 0x145c418/0x145c508/0x145c5e4 were proven GOT-anchor recomputes (all literals resolve; see INVENTORY_PICKUP_CURRENCY.md correction note) — stop edges remain the port boundary, tails manifest-only; no Foundation/app/device claim')
    (a.output_dir / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k != 'reports'}))
    print('mismatch counts:', [r['mismatch_count'] for r in reports])


if __name__ == '__main__':
    main()
