#!/usr/bin/env python3
"""Static contract for the minimal tree getSaveDict own-key pairings."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    r = json.loads((NATIVE / 'tree_savedict_keys.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    classes = {c['class']: c for c in r['classes']}
    assert list(classes) == ['AppleTree', 'PineTree', 'GemTree']
    for c in classes.values():
        assert c['style'] == 'super_plus_own_keys'
        assert c['super_site'].startswith('0x')
        assert c['super_class_struct'].startswith('0x00e9')
    at, pt, gt = classes['AppleTree'], classes['PineTree'], classes['GemTree']
    assert [k['key'] for k in at['keys']] == ['availableFood']
    assert [k['key'] for k in pt['keys']] == ['availableFood']
    assert [k['key'] for k in gt['keys']] == ['gemTreeType', 'fruitYear']
    for k in at['keys'] + pt['keys']:
        assert k['ivar_offset'] == 136 and k['conversion'] == 'numberWithFloat:'
    gem = {k['key']: k for k in gt['keys']}
    assert gem['gemTreeType']['ivar_offset'] == 136
    assert gem['gemTreeType']['conversion'] == 'numberWithInt:'
    assert gem['fruitYear']['ivar_offset'] == 140
    for c in classes.values():
        for k in c['keys']:
            assert k['ivar'] == f"OBJC_IVAR_$_{c['class']}.{k['key']}"
            assert k['set_object_site'].startswith('0x')
    # listings exist and carry the exact word coverage
    import re
    for name, words in (('disasm_appletree_getsavedict.txt', 78),
                        ('disasm_pinetree_getsavedict.txt', 79),
                        ('disasm_gemtree_getsavedict.txt', 112)):
        t = (NATIVE / name).read_text()
        assert t.count('# implementation: ') == 1
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)
    print('tree-savedict-keys-evidence: PASS')

if __name__ == '__main__':
    main()
