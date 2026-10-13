#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-2l save-key evidence.

On a host with the pinned ELF present, re-runs the recovery script and
asserts byte-identical JSON; on CI (ELF absent) falls back to static
content assertions plus listing word counts (same shape as b2i..b2k).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'subclass_savedict_keys_b2l.json'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if ELF.exists():
        r = subprocess.run(
            [sys.executable, str(ROOT / 'tools/recover_subclass_savedict_keys_b2l.py'),
             str(ELF), '--check'],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('stale subclass_savedict_keys_b2l.json')
        print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA, 'elf sha drift'
    assert d['method'] == 'getSaveDict key pairings (batch 2l)'
    classes = {c['class']: c for c in d['classes']}
    assert set(classes) == {'CaveTroll', 'Plant'}

    ct = classes['CaveTroll']
    assert ct['imp'] == '0x00d54924' and ct['boundary'] == '0x00d54e2c'
    assert ct['code_words'] == 322
    ctk = {k['key']: k for k in ct['keys']}
    assert set(ctk) == {'state', 'dead', 'defendSquare.x', 'defendSquare.y',
                        'attackingNPC', 'lastKnownNPCPosition.x',
                        'lastKnownNPCPosition.y'}
    st = ctk['state']
    assert st['conversion'] == 'dataWithBytes:length:'
    assert st['value_source'] == 'raw_buffer'
    assert st['raw_length'] == 0x24
    assert st['ivar'] == 'OBJC_IVAR_$_CaveTroll.state'
    assert st['ivar_offset'] == 208
    assert st['conversion_site'] == '0x00d54aa8'
    assert st['set_object_site'] == '0x00d54ad4'
    dead = ctk['dead']
    assert dead['conversion'] == 'numberWithBool:'
    assert dead['ivar'] == 'OBJC_IVAR_$_NPC.dead'
    assert dead['ivar_offset'] == 56
    an = ctk['attackingNPC']
    assert an['conversion'] == 'numberWithBool:'
    assert an['ivar'] == 'OBJC_IVAR_$_CaveTroll.chasingNPC'
    assert an['ivar_offset'] == 388
    assert an['conversion_site'] == '0x00d54cdc'
    for axis, iv, off in (('x', 'defendSquare', 356),
                          ('y', 'defendSquare', 356)):
        k = ctk[f'defendSquare.{axis}']
        assert k['conversion'] == 'numberWithInt:'
        assert k['ivar'] == f'OBJC_IVAR_$_CaveTroll.{iv}'
        assert k['ivar_offset'] == off
    for axis in ('x', 'y'):
        k = ctk[f'lastKnownNPCPosition.{axis}']
        assert k['conversion'] == 'numberWithInt:'
        assert k['ivar'] == \
            'OBJC_IVAR_$_CaveTroll.lastKnownNPCPosition'
        assert k['ivar_offset'] == 392
    gates = set(ct['site_gates'])
    for g in ('state_len_movw_0x24@0x00d54a0c', 'dead_ldrb@0x00d54af4',
              'chasing_ldrb@0x00d54c94', 'chasing_sxtb@0x00d54cac',
              'defend_x_word_ldr@0x00d54b54',
              'defend_y_word_ldr4@0x00d54bb4',
              'lknp_x_word_ldr@0x00d54d20',
              'lknp_y_word_ldr4@0x00d54d80'):
        assert g in gates, g

    pl = classes['Plant']
    assert pl['imp'] == '0x00955d7c' and pl['boundary'] == '0x0095649c'
    assert pl['code_words'] == 456
    plk = {k['key']: k for k in pl['keys']}
    assert set(plk) == {'saveTime', 'seasonOffset', 'age', 'gatherProgress',
                        'hasFloweredThisSeason', 'flowering', 'frozen',
                        'maxAgeGene', 'growthRateGene', 'maxAge',
                        'growthRate'}
    sv = plk['saveTime']
    assert sv['conversion'] == 'numberWithDouble:'
    assert sv['value_source'] == 'world_selector'
    assert sv['ivar'] is None
    assert sv['conversion_site'] == '0x00956020'
    assert sv['set_object_site'] == '0x00956044'
    for name, off, conv in (('seasonOffset', 68, 'numberWithInt:'),
                            ('gatherProgress', 80, 'numberWithInt:'),
                            ('maxAgeGene', 54, 'numberWithInt:'),
                            ('growthRateGene', 56, 'numberWithInt:'),
                            ('age', 72, 'numberWithFloat:'),
                            ('maxAge', 88, 'numberWithFloat:'),
                            ('growthRate', 92, 'numberWithFloat:'),
                            ('hasFloweredThisSeason', 84, 'numberWithBool:'),
                            ('flowering', 85, 'numberWithBool:'),
                            ('frozen', 76, 'numberWithBool:')):
        assert plk[name]['conversion'] == conv, name
        assert plk[name]['ivar'] == f'OBJC_IVAR_$_Plant.{name}'
        assert plk[name]['ivar_offset'] == off
    pg = set(pl['site_gates'])
    for g in ('worldtime_msg_site@0x00956000',
              'worldtime_vmov_d0@0x00956004',
              'hasflowered_ldrb@0x00956184',
              'flowering_ldrb@0x009561e4',
              'frozen_ldrb@0x00956244'):
        assert g in pg, g

    for name, words in (('disasm_cavetroll_getsavedict.txt', 322),
                        ('disasm_plant_getsavedict.txt', 456)):
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)

    print('b2l evidence: PASS')


if __name__ == '__main__':
    main()
