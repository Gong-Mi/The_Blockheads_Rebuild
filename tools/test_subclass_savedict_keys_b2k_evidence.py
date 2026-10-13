#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-2k save-key evidence.

On a host with the pinned ELF present (Termux working tree), re-runs
tools/recover_subclass_savedict_keys_b2k.py and asserts byte-identical
JSON with the checked-in subclass_savedict_keys_b2k.json.
On CI (ELF absent), falls back to static content assertions plus
listing word counts (same contract shape as the b2i/b2j evidence tests).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'subclass_savedict_keys_b2k.json'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if ELF.exists():
        r = subprocess.run(
            [sys.executable, str(ROOT / 'tools/recover_subclass_savedict_keys_b2k.py'),
             str(ELF), '--check'],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('stale subclass_savedict_keys_b2k.json')
        print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA, 'elf sha drift'
    assert d['method'] == 'getSaveDict key pairings (batch 2k)'
    classes = {c['class']: c for c in d['classes']}
    assert set(classes) == {'Boat', 'ArtificialLight', 'DropBear'}

    b = classes['Boat']
    assert b['imp'] == '0x0096c238' and b['boundary'] == '0x0096c674'
    assert b['code_words'] == 271
    bk = {k['key']: k for k in b['keys']}
    assert set(bk) == {'currentBlockheadIndex', 'ownerID'}
    cb = bk['currentBlockheadIndex']
    assert cb['conversion'] == 'numberWithInt:'
    assert cb['value_source'] == 'loop_index'
    assert cb['ivar'] is None
    assert cb['conversion_site'] == '0x0096c57c'
    assert cb['set_object_site'] == '0x0096c5a0'
    ow = bk['ownerID']
    assert ow['conversion'] == 'direct_object'
    assert ow['ivar'] == 'OBJC_IVAR_$_DynamicObject.ownerID'
    assert ow['ivar_offset'] == 36
    gates = set(b['site_gates'])
    for g in ('rider_guard_beq@0x0096c2c0', 'rider_bne@0x0096c440',
              'needsremoved_bne@0x0096c478', 'found_ldrsb@0x0096c510',
              'found_beq@0x0096c518', 'ownerid_guard_beq@0x0096c5cc'):
        assert g in gates, g

    al = classes['ArtificialLight']
    assert al['imp'] == '0x00a942d4' and al['boundary'] == '0x00a947ac'
    assert al['code_words'] == 310
    alk = {k['key']: k for k in al['keys']}
    assert set(alk) == {'maxRed', 'maxGreen', 'maxBlue', 'maxHeat',
                        'radius', 'contributionGridOrigin.x',
                        'contributionGridOrigin.y', 'lightDirection'}
    for name, off in (('maxRed', 64), ('maxGreen', 68), ('maxBlue', 72),
                      ('maxHeat', 76), ('radius', 80),
                      ('lightDirection', 96)):
        assert alk[name]['ivar'] == \
            f'OBJC_IVAR_$_ArtificialLight.{name}'
        assert alk[name]['ivar_offset'] == off
        assert alk[name]['conversion'] == 'numberWithInt:'
    for axis in ('x', 'y'):
        k = alk[f'contributionGridOrigin.{axis}']
        assert k['ivar'] == \
            'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin'
        assert k['ivar_offset'] == 84
        assert k['conversion'] == 'numberWithInt:'
    assert 'cgo_x_word_ldr@0x00a94640' in al['site_gates']
    assert 'cgo_y_word_ldr4@0x00a946a0' in al['site_gates']

    db = classes['DropBear']
    assert db['imp'] == '0x0079ddc0' and db['boundary'] == '0x0079e2b8'
    assert db['code_words'] == 318
    dbk = {k['key']: k for k in db['keys']}
    assert set(dbk) == {'provokeMeter', 'courageMeter', 'dropping',
                        'dropSpeed', 'onGround', 'dropPos.x', 'dropPos.y',
                        'goalTreeDirection'}
    for name, off, conv in (('provokeMeter', 300, 'numberWithFloat:'),
                            ('courageMeter', 304, 'numberWithFloat:'),
                            ('dropSpeed', 312, 'numberWithFloat:'),
                            ('dropping', 308, 'numberWithBool:'),
                            ('onGround', 344, 'numberWithBool:'),
                            ('goalTreeDirection', 356, 'numberWithBool:')):
        assert dbk[name]['conversion'] == conv, name
        assert dbk[name]['ivar'] == f'OBJC_IVAR_$_DropBear.{name}'
        assert dbk[name]['ivar_offset'] == off
    for axis in ('x', 'y'):
        k = dbk[f'dropPos.{axis}']
        assert k['conversion'] == 'numberWithBool:'
        assert k['ivar'] == 'OBJC_IVAR_$_DropBear.dropPos'
        assert k['ivar_offset'] == 348
    for g in ('dropping_ldrb@0x0079e028', 'onGround_ldrb@0x0079e0e8',
              'dropPos_x_ldr@0x0079e148', 'dropPos_y_ldr4@0x0079e1a8',
              'goalTree_ldr@0x0079e208', 'provoke_vldr@0x0079df44',
              'courage_vldr@0x0079dfc8', 'dropSpeed_vldr@0x0079e088'):
        assert g in db['site_gates'], g

    for name, words in (('disasm_boat_getsavedict.txt', 271),
                        ('disasm_artificiallight_getsavedict.txt', 310),
                        ('disasm_dropbear_getsavedict.txt', 318)):
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)

    print('b2k evidence: PASS')


if __name__ == '__main__':
    main()
