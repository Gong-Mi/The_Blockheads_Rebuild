#!/usr/bin/env python3
"""Static contract for batch 2g getSaveDict key pairings."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    r = json.loads((NATIVE / 'subclass_savedict_keys_b2g.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    cls = {c['class']: c for c in r['classes']}
    assert list(cls) == ['Rail', 'KelpPlant', 'VinePlant', 'Egg']
    rl = cls['Rail']
    assert [k['key'] for k in rl['keys']] == ['itemType', 'configuration', 'ownedByStation']
    assert rl['keys'][2]['conversion'] == 'numberWithBool:' and rl['keys'][2]['ivar_offset'] == 65
    assert rl['keys'][1]['ivar'] == 'OBJC_IVAR_$_Rail.currentConfiguration'
    kp, vp = cls['KelpPlant'], cls['VinePlant']
    assert [k['key'] for k in kp['keys']] == ['numberOfOccupiedTilesAbove', 'growthTimer', 'availableFood']
    assert [k['key'] for k in vp['keys']] == ['numberOfOccupiedTilesBelow', 'growthTimer', 'availableFood']
    assert kp['keys'][0]['ivar_offset'] == 200 and vp['keys'][0]['ivar_offset'] == 180
    assert kp['keys'][2]['ivar_offset'] == 180 and vp['keys'][2]['ivar_offset'] == 100
    assert all(k['conversion'] == 'numberWithFloat:' for k in kp['keys'][1:])
    assert all(k['conversion'] == 'numberWithFloat:' for k in vp['keys'][1:])
    eg = cls['Egg']
    assert [k['key'] for k in eg['keys']] == ['hatchTimer', 'saveTime', 'genesDict']  # exec order
    st = eg['keys'][1]
    assert st['conversion'] == 'world_time_derived'
    assert st['value_ivar'] == 'OBJC_IVAR_$_DynamicObject.world' and st['value_ivar_offset'] == 4
    assert eg['keys'][0]['ivar_offset'] == 64 and eg['keys'][2]['ivar_offset'] == 56
    assert eg['keys'][2]['conversion'] == 'direct_object'
    for name, words in (('disasm_rail_getsavedict.txt', 159),
                        ('disasm_kelpplant_getsavedict.txt', 160),
                        ('disasm_vineplant_getsavedict.txt', 160),
                        ('disasm_egg_getsavedict.txt', 171)):
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)
    print('subclass-savedict-keys-b2g-evidence: PASS')

if __name__ == '__main__':
    main()
