#!/usr/bin/env python3
"""Generate the batch-2h pairing table mechanically from annotated listings
+ freeblock simulator (same pipeline as gen_b2f_table, parameterised)."""
import json, os, re, subprocess, sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
NATIVE = TOOLS.parent / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'

BODIES = {
 'TulipPlant':   ('disasm_tulipplant_getsavedict.txt',   0x009A1854, 0x009A1B14),
 'SteamTrain':   ('disasm_steamtrain_getsavedict.txt',   0x00D18E84, 0x00D19144),
 'OwnershipSign':('disasm_ownershipsign_getsavedict.txt',0x00A358E4, 0x00A35BCC),
 'CactusTree':   ('disasm_cactustree_getsavedict.txt',   0x00B53728, 0x00B53A08),
}


def sim(imp, pool):
    env = {**os.environ, 'LD_LIBRARY_PATH': os.environ.get('PREFIX', '') + '/lib'}
    out = subprocess.run(['python3', str(TOOLS / 'freeblock_save_key_flow.py'),
                          str(ELF), hex(imp), hex(pool)],
                         capture_output=True, text=True, env=env).stdout
    return json.loads(out)['resolved_sites']


def main():
    for cls, (listing, imp, pool) in BODIES.items():
        text = (NATIVE / listing).read_text()
        words = {int(m.group(1), 16): m.group(2)
                 for m in re.finditer(r'0x([0-9a-f]{8})\s+([0-9a-f]{8})', text)}
        sites = sim(imp, pool)
        # walk: conv sel+site followed by set site with key
        pending = None
        for r in sites:
            sel, site = r['r1_sel'], int(r['site'], 16)
            if sel and sel.startswith('numberWith'):
                pending = (sel, site)
            elif sel == 'setObject:forKey:':
                conv = pending if (pending and pending[1] < site) else (None, None)
                # find conv selref cell: nearest ldr-annotated selref of that selector before conv site
                csel_cell = None
                if conv[1]:
                    best = -1
                    for m in re.finditer(
                            r"0x([0-9a-f]{8})\s+[0-9a-f]{8}\s+\w+.*-> selref/cstring @0x[0-9a-f]{8} '"
                            + re.escape(conv[0]) + "'", text):
                        a = int(m.group(1), 16)
                        if a < conv[1] and a > best:
                            best = a
                    mm = re.search(
                        r"0x%08x\s+[0-9a-f]{8}\s+\w+ \w+, \[pc, #0x[0-9a-f]+\].*?; \[(0x[0-9a-f]{8}):4\]" % best,
                        text) if best >= 0 else None
                    csel_cell = int(mm.group(1), 16) if mm else None
                # set selref cell: any setObject annotation (shared)
                sset = re.search(r"; \[(0x[0-9a-f]{8}):4\]=\S+ -> selref/cstring @0x[0-9a-f]{8} 'setObject:forKey:'", text)
                # CFString cell for key: annotation on nearest ldr before set site
                key = r['r3_key']
                kcell, cobj = None, None
                for m in re.finditer(
                        r"0x([0-9a-f]{8})\s+[0-9a-f]{8}\s+ldr \w+, \[pc.*?; \[(0x[0-9a-f]{8}):4\]=0x[0-9a-f]+ -> CFString key obj @0x([0-9a-f]{8}) '" + re.escape(key) + "'",
                        text):
                    a = int(m.group(1), 16)
                    if a < site:
                        kcell, cobj = int(m.group(2), 16), int(m.group(3), 16)
                # ivar cell: prefer <cls>.<key>, then current variants
                iv = None
                cands = [f'OBJC_IVAR_$_{cls}.{key}',
                         f'OBJC_IVAR_$_{cls}.current{key[0].upper() + key[1:]}',
                         f'OBJC_IVAR_$_{cls}.{key.lower()}',
                         f'OBJC_IVAR_$_DynamicObject.{key}']
                for m in re.finditer(
                        r"0x([0-9a-f]{8})\s+[0-9a-f]{8}\s+ldr \w+, \[pc.*?; \[(0x[0-9a-f]{8}):4\]=0x[0-9a-f]+ -> ivar-offset storage (OBJC_IVAR_\$\S+) \(slot 0x[0-9a-f]{8}\) = (\d+)",
                        text):
                    a, cell, sym, off = (int(m.group(1), 16), int(m.group(2), 16), m.group(3), int(m.group(4)))
                    if sym in cands and (iv is None or a > iv[0]):
                        # prefer nearest ldr before the conv (value-load) or before set
                        ref = conv[1] if conv[1] else site
                        if a < ref + 0x400:
                            iv = (a, cell, sym, off)
                nc = re.search(r"; \[(0x[0-9a-f]{8}):4\]=\S+ -> classref OBJC_CLASS_\$_NSNumber", text)
                print((cls, key, kcell, cobj,
                       (iv[2], iv[3], iv[1]) if iv else (None, None, None),
                       conv[0] if pending else None,
                       conv[1], words.get(conv[1]) if conv[1] else None,
                       int(nc.group(1), 16) if nc and conv[0] else None,
                       csel_cell,
                       site, words[site], int(sset.group(1), 16)))
                pending = None


if __name__ == '__main__':
    main()
