#!/usr/bin/env python3
"""Static contract for batch 2d getSaveDict key pairings."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    r = json.loads((NATIVE / 'subclass_savedict_keys_b2d.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    cls = {c['class']: c for c in r['classes']}
    pc = cls['PaintingCraftableItemObject']
    assert [k['key'] for k in pc['keys']] == ['imageData', 'outputImageData', 'craftableObjectType']
    assert pc['keys'][0]['conversion'] == 'direct_object' and pc['keys'][0]['ivar_offset'] == 128
    assert pc['keys'][1]['ivar_offset'] == 132
    assert pc['keys'][2]['conversion'] == 'numberWithInt:'
    assert pc['keys'][2].get('value_source') == 'pending (value cell not gated)'
    np = cls['NormalPlant']
    assert [k['key'] for k in np['keys']] == ['availableFood', 'lightDict']
    assert np['keys'][0]['ivar'] == 'OBJC_IVAR_$_NormalPlant.availableFood'
    assert np['keys'][1]['conversion'] == 'nested_getSaveDict'
    assert np['keys'][1]['ivar'] == 'OBJC_IVAR_$_NormalPlant.light'
    assert np['guard']['emits_light_selref'] == 'emitsLight'
    gb = cls['GlowBlock']
    assert [k['key'] for k in gb['keys']] == ['tileType', 'lightDict']
    assert gb['keys'][1]['conversion'] == 'nested_getSaveDict'
    assert gb['keys'][1]['ivar'] == 'OBJC_IVAR_$_GlowBlock.light'
    ga = cls['GatherBlock']
    assert [k['key'] for k in ga['keys']] == ['timer', 'lastKnownGatherValue']  # exec order
    assert ga['keys'][0]['conversion'] == 'numberWithFloat:' and ga['keys'][0]['ivar_offset'] == 56
    assert ga['keys'][1]['conversion'] == 'numberWithInt:' and ga['keys'][1]['ivar_offset'] == 60
    for name, words in (('disasm_paintingcico_getsavedict.txt', 129),
                        ('disasm_normalplant_getsavedict.txt', 136),
                        ('disasm_glowblock_getsavedict.txt', 123),
                        ('disasm_gatherblock_getsavedict.txt', 122)):
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)
    print('subclass-savedict-keys-b2d-evidence: PASS')

if __name__ == '__main__':
    main()
