#!/usr/bin/env python3
"""Static contract for batch 2b item subclass getSaveDict pairings."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    r = json.loads((NATIVE / 'item_savedict_keys.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    classes = {c['class']: c for c in r['classes']}
    assert list(classes) == ['Bed', 'TrainStation', 'CraftableItemObject']
    bed = classes['Bed']
    assert bed['style'] == 'super_plus_own_keys'
    assert [k['key'] for k in bed['keys']] == ['itemType', 'beddingColor']  # execution order
    assert [k['ivar_offset'] for k in bed['keys']] == [100, 104]
    assert all(k['conversion'] == 'numberWithInt:' for k in bed['keys'])
    ts = classes['TrainStation']
    assert ts['keys'][0]['key'] == 'text' and ts['keys'][0]['ivar_offset'] == 128
    assert ts['keys'][0]['conversion'] == 'direct_object'
    co = classes['CraftableItemObject']
    assert co['style'] == 'fresh_dictionary_pod_blob'
    k = co['keys'][0]
    assert k['key'] == 'craftableItem' and k['ivar_offset'] == 4
    assert k['conversion'] == 'dataWithBytes:length:' and k['struct_length'] == 124
    for cls in classes.values():
        if cls['style'] == 'super_plus_own_keys':
            assert cls['super_site'].startswith('0x')
    for name, words in (('disasm_bed_getsavedict.txt', 112),
                        ('disasm_trainstation_getsavedict.txt', 68),
                        ('disasm_craftableitemobject_getsavedict.txt', 78)):
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)
    print('item-savedict-keys-b2b-evidence: PASS')

if __name__ == '__main__':
    main()
