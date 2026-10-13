#!/usr/bin/env python3
"""Static contract for batch 2i getSaveDict key pairings."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    r = json.loads((NATIVE / 'subclass_savedict_keys_b2i.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    cls = {c['class']: c for c in r['classes']}
    assert list(cls) == ['Sign', 'ElevatorMotor', 'ElevatorShaft', 'Painting']
    sg = cls['Sign']
    assert [k['key'] for k in sg['keys']] == ['text', 'ownerID', 'ownerName',
                                              'connectionType', 'offsetType']
    assert [k['ivar_offset'] for k in sg['keys']] == [100, 36, 84, 112, 116]
    assert all(k['conversion'] == 'direct_object' for k in sg['keys'][:3])
    assert sg['keys'][2]['ivar'] == 'OBJC_IVAR_$_InteractionObject.ownerName'
    assert all(k['conversion'] == 'numberWithInt:' for k in sg['keys'][3:])
    em = cls['ElevatorMotor']
    assert [k['key'] for k in em['keys']] == ['itemType', 'availableElectricity',
                                              'minY', 'maxY', 'ownerID']
    assert [k['ivar_offset'] for k in em['keys']] == [56, 60, 64, 68, 36]
    assert em['keys'][0]['conversion'] == 'numberWithInt:'
    assert all(k['conversion'] == 'numberWithUnsignedInt:' for k in em['keys'][1:4])
    es = cls['ElevatorShaft']
    assert [k['key'] for k in es['keys']] == ['itemType', 'lastKnownMotorPos.x',
                                              'lastKnownMotorPos.y', 'paintColor',
                                              'ownerID']
    assert es['keys'][1]['ivar'] == 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos'
    assert es['keys'][2]['ivar'] == es['keys'][1]['ivar']
    assert es['keys'][3]['conversion'] == 'numberWithUnsignedInt:'
    pt = cls['Painting']
    assert [k['key'] for k in pt['keys']] == ['itemType', 'outputImageData',
                                              'ownerID', 'ownerName',
                                              'hasVerifiedImageData']
    assert pt['keys'][1]['ivar'] == 'OBJC_IVAR_$_Painting.imageData'
    assert pt['keys'][1]['conversion'] == 'direct_object'
    assert pt['keys'][4]['ivar_offset'] == 79
    assert pt['keys'][4]['conversion'] == 'numberWithBool:'
    for name, words in (('disasm_sign_getsavedict.txt', 216),
                        ('disasm_elevatormotor_getsavedict.txt', 223),
                        ('disasm_elevatorshaft_getsavedict.txt', 223),
                        ('disasm_painting_getsavedict.txt', 242)):
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)
    print('subclass-savedict-keys-b2i-evidence: PASS')

if __name__ == '__main__':
    main()
