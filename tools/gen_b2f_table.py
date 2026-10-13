#!/usr/bin/env python3
"""Generate the batch-2f pairing table mechanically from annotated listings
and the freeblock forward simulator (extraction-first workflow)."""
import json
import re
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
NATIVE = TOOLS.parent / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'

BODIES = {  # class: (listing, imp, super_site, pool_start_cell)
 'Column': ('disasm_column_getsavedict.txt', 0x00835094, 0x008350E8, 0x00835340, 0x00835184),
 'Stairs': ('disasm_stairs_getsavedict.txt', 0x006CCD98, 0x006CCDEC, 0x006CD044, 0x006CCE78),
 'Door':   ('disasm_door_getsavedict.txt', 0x00769DC8, 0x00769E1C, 0x0076A06C, 0x00769E78),
 'Wire':   ('disasm_wire_getsavedict.txt', 0x00950770, 0x009507C4, 0x00950A24, 0x00950850),
}
BOUNDARIES = {'Column': 0x00835384, 'Stairs': 0x006CD088,
              'Door': 0x0076A0AC, 'Wire': 0x00950A64}


def sim_resolved(imp_end, pool):
    out = subprocess.run(['python3', str(TOOLS / 'freeblock_save_key_flow.py'),
                          str(ELF), hex(imp_end), hex(pool)],
                         capture_output=True, text=True,
                         env={**__import__('os').environ, 'LD_LIBRARY_PATH': str(Path.home() / 'blockheads-work')}
                         ).stdout
    return json.loads(out)['resolved_sites']


def main():
    rows = []
    for cls, (listing, imp, super_site, got_cell, code_end) in BODIES.items():
        text = (NATIVE / listing).read_text()
        # word lookup
        words = {int(m.group(1), 16): m.group(2)
                 for m in re.finditer(r'0x([0-9a-f]{8})\s+([0-9a-f]{8})', text)}
        # simulator chain in body order
        sites = sim_resolved(imp, got_cell)
        super_row = sites[0]
        assert super_row['r1_sel'] == 'getSaveDict'
        sw = words[int(super_row['site'], 16)]
        # pair conv->set by walking resolved sites in order
        pending_conv = None
        triples = []
        for r in sites[1:]:
            sel = r['r1_sel']
            if sel in ('numberWithInt:', 'numberWithFloat:', 'numberWithBool:',
                       'numberWithUnsignedInt:', 'numberWithUnsignedLong:'):
                pending_conv = (sel, int(r['site'], 16))
            elif sel == 'setObject:forKey:':
                triples.append((r['r3_key'], pending_conv, int(r['site'], 16)))
                pending_conv = None
        # CFString cells: literal cell whose annotation is "CFString key obj ... 'key'"
        cfcells = {}
        for m in re.finditer(r'; \[(0x[0-9a-f]{8}):4\]=0x[0-9a-f]+ -> CFString key obj @0x([0-9a-f]{8}) \'([^\']+)\'', text):
            cfcells[m.group(3)] = (int(m.group(1), 16), int(m.group(2), 16))
        # ivar cells: annotation "ivar-offset storage SYM (slot X) = N"
        ivcells = {}
        for m in re.finditer(r'; \[(0x[0-9a-f]{8}):4\]=\S+ -> ivar-offset storage (OBJC_IVAR_\$_[^\s]+) \(slot 0x[0-9a-f]{8}\) = (\d+)', text):
            ivcells[m.group(2)] = (int(m.group(1), 16), int(m.group(3)))
        # selref cells for setObject and each conv selector
        def sel_cell(name):
            m = re.search(r'; \[(0x[0-9a-f]{8}):4\]=\S+ -> selref/cstring @0x[0-9a-f]{8} \'' + re.escape(name) + "'", text)
            return int(m.group(1), 16)

        def conv_selref_before(site):
            best = None
            for m in re.finditer(r'0x([0-9a-f]{8})\s+[0-9a-f]{8}\s+ldr \w+, \[pc.*?; \[(0x[0-9a-f]{8}):4\]=\S+ -> selref/cstring @0x[0-9a-f]{8} \'' + re.escape(sel_of(site)) + "'", text):
                a = int(m.group(1), 16)
                if a < site and (best is None or a > best[0]):
                    best = (a, int(m.group(2), 16))
            return best[1] if best else None
        numcell = re.search(r'; \[(0x[0-9a-f]{8}):4\]=\S+ -> classref OBJC_CLASS_\$_NSNumber', text).group(1)
        set_cell = sel_cell('setObject:forKey:')
        def sel_of(site):
            for k2, c2, s2 in triples:
                if c2 and c2[1] == site:
                    return c2[0]
            raise KeyError(site)

        for key, conv, set_site in triples:
            conv_sel, conv_site = conv if conv else (None, None)
            ivsym, icell = None, None
            if key in cfcells:
                pass
            # ivar for key: prefer <cls>.<key>, else <cls>.current<Key capitalized>, else DynamicObject.ownerID / direct by name match on tail
            cands = [f'OBJC_IVAR_$_{cls}.{key}',
                     f'OBJC_IVAR_$_{cls}.current{key.capitalize()}',
                     f'OBJC_IVAR_$_{cls}.current{key[0].upper() + key[1:]}',
                     f'OBJC_IVAR_$_DynamicObject.{key}']
            for cand in cands:
                if cand in ivcells:
                    ivsym = cand
                    icell = ivcells[cand][0]
                    break
            rows.append((cls, key, cfcells.get(key, (None, None))[0],
                         cfcells.get(key, (None, None))[1],
                         ivsym,
                         ivcells[ivsym][1] if ivsym else None,
                         conv_sel, conv_site,
                         words.get(conv_site) if conv_site else None,
                         int(numcell, 16) if conv_sel else None,
                         set_site, words[set_site], set_cell,
                         conv_selref_before(conv_site) if conv_site else None))
    for r in rows:
        print(r)
    print('rows', len(rows))


if __name__ == '__main__':
    main()
