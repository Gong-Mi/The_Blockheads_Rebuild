#!/usr/bin/env python3
"""Static contract for batch 2h getSaveDict key pairings."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    r = json.loads((NATIVE / 'subclass_savedict_keys_b2h.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    cls = {c['class']: c for c in r['classes']}
    assert list(cls) == ['TulipPlant', 'SteamTrain', 'OwnershipSign', 'CactusTree']
    tp = cls['TulipPlant']
    assert [k['key'] for k in tp['keys']] == ['availableFood', 'colorGenes', 'mixGenes', 'mateColorGenes']
    assert [k['ivar_offset'] for k in tp['keys']] == [100, 112, 114, 116]
    assert tp['keys'][0]['conversion'] == 'numberWithFloat:'
    st = cls['SteamTrain']
    assert [k['key'] for k in st['keys']] == ['fuelFraction', 'hasFuel', 'goingRight', 'stopped']
    assert [k['ivar_offset'] for k in st['keys']] == [260, 268, 252, 325]
    assert st['keys'][0]['conversion'] == 'numberWithFloat:'
    assert all(k['conversion'] == 'numberWithBool:' for k in st['keys'][1:])
    os_ = cls['OwnershipSign']
    assert [k['key'] for k in os_['keys']] == ['landOwnerID', 'landOwnerName', 'w', 'h']
    assert os_['keys'][0]['conversion'] == 'direct_object'
    assert os_['keys'][0]['ivar'] == 'OBJC_IVAR_$_OwnershipSign.landOwnerID'
    assert os_['keys'][0]['ivar_offset'] == 124
    assert os_['keys'][2]['ivar'] == 'OBJC_IVAR_$_OwnershipSign.widthRadius'
    assert os_['keys'][3]['ivar'] == 'OBJC_IVAR_$_OwnershipSign.heightRadius'
    ct = cls['CactusTree']
    assert [k['key'] for k in ct['keys']] == ['splitHeightA', 'splitHeightB', 'splitDirection', 'availableFood']
    assert [k['ivar_offset'] for k in ct['keys']] == [136, 140, 144, 148]
    assert ct['keys'][2]['conversion'] == 'numberWithBool:'
    assert ct['keys'][3]['conversion'] == 'numberWithFloat:'
    for name, words in (('disasm_tulipplant_getsavedict.txt', 193),
                        ('disasm_steamtrain_getsavedict.txt', 193),
                        ('disasm_ownershipsign_getsavedict.txt', 202),
                        ('disasm_cactustree_getsavedict.txt', 202)):
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)
    print('subclass-savedict-keys-b2h-evidence: PASS')

if __name__ == '__main__':
    main()
