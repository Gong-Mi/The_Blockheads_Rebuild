#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-2n save-key evidence.

On a host with the pinned ELF present, re-runs the recovery script and
asserts byte-identical JSON; on CI (ELF absent) falls back to static
content assertions plus listing word counts (same shape as b2i..b2m).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'subclass_savedict_keys_b2n.json'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if ELF.exists():
        r = subprocess.run(
            [sys.executable, str(ROOT / 'tools/recover_subclass_savedict_keys_b2n.py'),
             str(ELF), '--check'],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('stale subclass_savedict_keys_b2n.json')
        print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA, 'elf sha drift'
    assert d['method'] == 'getSaveDict key pairings (batch 2n)'
    tc = {c['class']: c for c in d['classes']}['TrainCar']
    assert tc['imp'] == '0x00a394b0' and tc['boundary'] == '0x00a39d64'
    assert tc['code_words'] == 557
    k = {x['key']: x for x in tc['keys']}
    assert set(k) == {'currentBlockheadIndex_%d', 'rightCarID',
                      'leftCarID', 'engineCarID', 'ownerID',
                      'engineIsRight'}
    dyn = k['currentBlockheadIndex_%d']
    assert dyn['key_kind'] == 'format_string'
    assert dyn['cfstring_object'] == '0x00f972a8'
    assert dyn['value_source'] == 'blockhead_index_per_occupied_slot'
    assert dyn['conversion'] == 'numberWithInt:'
    assert dyn['conversion_site'] == '0x00a39878'
    assert dyn['set_object_site'] == '0x00a398c4'
    for name, off, conv, src in (
            ('rightCarID', 168, 'numberWithInt:', 'neighbor_uniqueID'),
            ('leftCarID', 172, 'numberWithInt:', 'neighbor_uniqueID'),
            ('engineCarID', 176, 'numberWithInt:', 'neighbor_uniqueID')):
        assert k[name]['conversion'] == conv, name
        assert k[name]['value_source'] == src, name
        assert k[name]['ivar'] == f'OBJC_IVAR_$_TrainCar.{name.replace("ID", "")}'
        assert k[name]['ivar_offset'] == off
    ow = k['ownerID']
    assert ow['conversion'] == 'direct_object'
    assert ow['ivar'] == 'OBJC_IVAR_$_DynamicObject.ownerID'
    assert ow['ivar_offset'] == 36
    assert ow['set_object_site'] == '0x00a39c2c'
    er = k['engineIsRight']
    assert er['conversion'] == 'numberWithBool:'
    assert er['ivar'] == 'OBJC_IVAR_$_TrainCar.engineIsRight'
    assert er['ivar_offset'] == 180
    assert er['conversion_site'] == '0x00a39ca8'
    assert er['set_object_site'] == '0x00a39ccc'
    gates = set(tc['site_gates'])
    for g in ('maxriders_msg_site@0x00a39550',
              'riders_slot_ldr@0x00a3958c',
              'riders_slot_nil_beq@0x00a39598',
              'rider_enumerate_site@0x00a39618',
              'needsremoved_msg_site@0x00a39748',
              'found_ldrsb@0x00a397ec',
              'found_beq@0x00a397f4',
              'rightcar_guard_beq@0x00a39904',
              'leftcar_guard_beq@0x00a399f4',
              'enginecar_guard_beq@0x00a39ae4',
              'engineisright_ldrb@0x00a39c7c',
              'engineisright_sxtb@0x00a39c8c'):
        assert g in gates, g

    t = (NATIVE / 'disasm_traincar_getsavedict.txt').read_text()
    n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
    assert n == 557, n

    print('b2n evidence: PASS')


if __name__ == '__main__':
    main()
