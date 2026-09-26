#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-2p save-key evidence.

On a host with the pinned ELF present, re-runs the recovery script and
asserts byte-identical JSON; on CI (ELF absent) falls back to static
content assertions plus listing word counts (same shape as b2i..b2o).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'subclass_savedict_keys_b2p.json'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if ELF.exists():
        r = subprocess.run(
            [sys.executable, str(ROOT / 'tools/recover_subclass_savedict_keys_b2p.py'),
             str(ELF), '--check'],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('stale subclass_savedict_keys_b2p.json')
        print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA, 'elf sha drift'
    assert d['method'] == 'getSaveDict key pairings (batch 2p)'
    wb = {c['class']: c for c in d['classes']}['Workbench']
    assert wb['imp'] == '0x00ae81d0' and wb['boundary'] == '0x00ae9510'
    assert wb['code_words'] == 1232
    k = {x['key']: x for x in wb['keys']}
    assert len(k) == 21
    assert set(k) == {'workbenchType', 'selectedIndex', 'xScroll', 'level',
                      'craftProgressCount', 'hurryTimer', 'hurrySeconds',
                      'hurrying', 'hurryCost', 'availableElectricity',
                      'fireSpreadTimer', 'fuelFraction', 'hasFuel',
                      'lastWorldTime', 'currentBlockheadIndexFuel',
                      'craftingItemDatav2', 'count', 'countLeft',
                      'countCreated', 'lightDict', 'sourceItems_%d'}
    wt = k['workbenchType']
    assert wt['ivar'] == 'OBJC_IVAR_$_Workbench.type'
    assert wt['ivar_offset'] == 120
    assert wt['conversion'] == 'numberWithInt:'
    lw = k['lastWorldTime']
    assert lw['conversion'] == 'numberWithDouble:'
    assert lw['ivar'] == 'OBJC_IVAR_$_Workbench.lastWorldTime'
    assert lw['ivar_offset'] == 256
    ae = k['availableElectricity']
    assert ae['conversion'] == 'numberWithUnsignedInt:'
    assert ae['ivar_offset'] == 222
    cf = k['currentBlockheadIndexFuel']
    assert cf['conversion'] == 'numberWithInt:'
    assert cf['value_source'] == 'loop_index'
    assert cf['ivar'] is None
    cid = k['craftingItemDatav2']
    assert cid['conversion'] == 'direct_object'
    assert cid['value_source'] == 'nested_getSaveDict'
    assert cid['ivar'] == 'OBJC_IVAR_$_Workbench.craftingItemObject'
    assert cid['ivar_offset'] == 180
    ld = k['lightDict']
    assert ld['conversion'] == 'direct_object'
    assert ld['value_source'] == 'nested_getSaveDict'
    assert ld['ivar'] == 'OBJC_IVAR_$_Workbench.light'
    assert ld['ivar_offset'] == 100
    si = k['sourceItems_%d']
    assert si['key_kind'] == 'format_string'
    assert si['cfstring_object'] == '0x00f9bb18'
    assert si['value_source'] == 'per_index_saveData_arrays'
    for name, off, conv in (('count', 228, 'numberWithInt:'),
                           ('countLeft', 232, 'numberWithInt:'),
                           ('countCreated', 236, 'numberWithInt:'),
                           ('hurryTimer', 192, 'numberWithFloat:'),
                           ('hurrySeconds', 196, 'numberWithFloat:'),
                           ('hurrying', 200, 'numberWithBool:'),
                           ('hurryCost', 204, 'numberWithInt:'),
                           ('fireSpreadTimer', 208, 'numberWithFloat:'),
                           ('fuelFraction', 212, 'numberWithFloat:'),
                           ('hasFuel', 220, 'numberWithBool:'),
                           ('xScroll', 172, 'numberWithFloat:'),
                           ('level', 176, 'numberWithInt:'),
                           ('craftProgressCount', 188, 'numberWithFloat:'),
                           ('selectedIndex', 136, 'numberWithInt:')):
        assert k[name]['conversion'] == conv, name
        assert k[name]['ivar_offset'] == off, name
    gates = set(wb['site_gates'])
    for g in ('super_site@0x00ae8228',
              'fuel_enumerate@0x00ae8ac0',
              'nested_getsavedict_msg@0x00ae8d2c',
              'nested_guard_beq@0x00ae8d40',
              'sourceitems_count_msg@0x00ae9074',
              'sourceitems_array_create@0x00ae90bc',
              'sourceitems_addobject_selref@0x00ae9218',
              'light_nested_msg@0x00ae9424'):
        assert g in gates, g
    # pending gates recorded, not asserted as resolved
    assert any('craftableitem' in p for p in wb.get('pending_gates', []))

    t = (NATIVE / 'disasm_workbench_getsavedict.txt').read_text()
    n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
    assert n == 1232, n

    print('b2p evidence: PASS')


if __name__ == '__main__':
    main()
