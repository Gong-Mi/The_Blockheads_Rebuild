#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-2m save-key evidence.

On a host with the pinned ELF present, re-runs the recovery script and
asserts byte-identical JSON; on CI (ELF absent) falls back to static
content assertions plus listing word counts (same shape as b2i..b2l).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'subclass_savedict_keys_b2m.json'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if ELF.exists():
        r = subprocess.run(
            [sys.executable, str(ROOT / 'tools/recover_subclass_savedict_keys_b2m.py'),
             str(ELF), '--check'],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('stale subclass_savedict_keys_b2m.json')
        print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA, 'elf sha drift'
    assert d['method'] == 'getSaveDict key pairings (batch 2m)'
    io = {c['class']: c for c in d['classes']}['InteractionObject']
    assert io['imp'] == '0x005f50b8' and io['boundary'] == '0x005f58c0'
    assert io['code_words'] == 514
    k = {x['key']: x for x in io['keys']}
    assert set(k) == {'saveTime', 'isInUse', 'flipped',
                      'interactionObjectType', 'paintColor',
                      'currentBlockheadIndex', 'ownerID', 'ownerName'}
    sv = k['saveTime']
    assert sv['conversion'] == 'numberWithDouble:'
    assert sv['value_source'] == 'world_selector'
    assert sv['ivar'] is None
    assert sv['conversion_site'] == '0x005f52b8'
    assert sv['set_object_site'] == '0x005f52dc'
    for name, off, conv in (('isInUse', 68, 'numberWithBool:'),
                            ('flipped', 69, 'numberWithBool:'),
                            ('paintColor', 88, 'numberWithUnsignedInt:')):
        assert k[name]['conversion'] == conv, name
        assert k[name]['ivar'] == f'OBJC_IVAR_$_InteractionObject.{name}'
        assert k[name]['ivar_offset'] == off
    ot = k['interactionObjectType']
    assert ot['conversion'] == 'numberWithInt:'
    assert ot['value_source'] == 'computed_selector'
    assert ot['ivar'] is None
    assert ot['conversion_site'] == '0x005f53e4'
    assert ot['set_object_site'] == '0x005f5408'
    cb = k['currentBlockheadIndex']
    assert cb['conversion'] == 'numberWithInt:'
    assert cb['value_source'] == 'loop_index'
    assert cb['conversion_site'] == '0x005f570c'
    assert cb['set_object_site'] == '0x005f5730'
    ow = k['ownerID']
    assert ow['conversion'] == 'direct_object'
    assert ow['ivar'] == 'OBJC_IVAR_$_DynamicObject.ownerID'
    assert ow['ivar_offset'] == 36
    assert ow['set_object_site'] == '0x005f57b4'
    on = k['ownerName']
    assert on['conversion'] == 'direct_object'
    assert on['ivar'] == 'OBJC_IVAR_$_InteractionObject.ownerName'
    assert on['ivar_offset'] == 84
    assert on['set_object_site'] == '0x005f5834'
    gates = set(io['site_gates'])
    for g in ('currentblockhead_guard_beq@0x005f5488',
              'enumerate_site@0x005f5508',
              'identity_cmp@0x005f5600',
              'identity_bne@0x005f5608',
              'found_ldrsb@0x005f56a0',
              'found_beq@0x005f56a8',
              'isInUse_ldrb@0x005f52fc',
              'flipped_ldrb@0x005f535c',
              'worldtime_msg_site@0x005f5298',
              'worldtime_vmov_d0@0x005f529c',
              'ownerid_guard_beq@0x005f575c',
              'ownername_guard_beq@0x005f57dc'):
        assert g in gates, g

    t = (NATIVE / 'disasm_interactionobject_getsavedict.txt').read_text()
    n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
    assert n == 514, n

    print('b2m evidence: PASS')


if __name__ == '__main__':
    main()
