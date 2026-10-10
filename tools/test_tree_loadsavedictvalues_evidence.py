#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-b3a Tree load evidence.

On a host with the pinned ELF present, re-runs the recovery script and
asserts byte-identical JSON; on CI (ELF absent) falls back to static
content assertions plus listing word counts (same shape as b2i..b2p).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'tree_loadsavedictvalues.json'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if ELF.exists():
        r = subprocess.run(
            [sys.executable, str(ROOT / 'tools/recover_tree_loadsavedictvalues.py'),
             str(ELF), '--check'],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('stale tree_loadsavedictvalues.json')
        print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA, 'elf sha drift'
    assert 'loadSaveDictValues' in d['method']
    assert d['imp'] == '0x004c2df0' and d['boundary'] == '0x004c39a0'
    assert d['code_words'] == 748
    chains = {c['key']: c for c in d['chains']}
    assert set(chains) == {'treeSeasonOffset', 'dead', 'timeDied',
                           'removeCheckCount'}
    tso = chains['treeSeasonOffset']
    assert tso['conversion'] == 'intValue' and tso['store_kind'] == 'word_store'
    assert tso['ivar_offset'] == 84
    dd = chains['dead']
    assert dd['conversion'] == 'boolValue' and dd['store_kind'] == 'byte_store'
    assert dd['ivar_offset'] == 104
    td = chains['timeDied']
    assert td['conversion'] == 'doubleValue'
    assert td['store_kind'] == 'double_store'
    assert td['ivar_offset'] == 112
    rcc = chains['removeCheckCount']
    assert rcc['conversion'] == 'floatValue'
    assert rcc['store_kind'] == 'float_store'
    assert rcc['ivar_offset'] == 120
    tf = d['treeFruit']
    assert tf['fruitcount_reset'] is True
    assert tf['record_stride'] == 0xc
    assert set(tf['fruit_keys']) == {'pos.x', 'pos.y',
                                    'hasCreatedFreeBlockThisSeason'}
    assert d['isStaticTree_gate']['bne'] == '0x004c3570'
    assert d['saveTime_read_back'] is False
    assert 'saveTime' not in d['pool_keys']
    assert len(d['pool_keys']) == 17
    gates = set(d['site_gates'])
    for g in ('treeFruit_objectforkey_site@0x004c3058',
              'fruitcount_reset_store@0x004c3074',
              'fruit_enumerate_site@0x004c30b8',
              'fruit_empty_beq@0x004c30c4',
              'fruit_stride_movw_0xc@0x004c32a8',
              'isstatictree_sxtb@0x004c3568',
              'isstatictree_bne@0x004c3570'):
        assert g in gates, g

    t = (NATIVE / 'disasm_tree_loadsavedictvalues.txt').read_text()
    n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
    assert n == 748, n
    # saveTime must not appear as a read key in the listing either
    assert "'saveTime'" not in t

    print('b3a evidence: PASS')


if __name__ == '__main__':
    main()
