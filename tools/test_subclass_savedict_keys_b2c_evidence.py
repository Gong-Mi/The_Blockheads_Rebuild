#!/usr/bin/env python3
"""Static contract for batch 2c getSaveDict shapes."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    r = json.loads((NATIVE / 'subclass_savedict_keys_b2c.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    cls = {c['class']: c for c in r['classes']}
    ssb = cls['SnowSurfaceBlock']
    assert ssb['style'] == 'cached_dict_accessor' and ssb['code_words'] == 15
    assert ssb['cached_ivar'] == 'OBJC_IVAR_$_SnowSurfaceBlock.saveDictCached'
    assert ssb['cached_ivar_offset'] == 64
    w = cls['Window']
    assert [k['key'] for k in w['keys']] == ['itemType', 'ownerID']
    assert w['keys'][0]['conversion'] == 'numberWithInt:'
    assert w['keys'][1]['conversion'] == 'direct_object'
    assert w['keys'][1]['ivar'] == 'OBJC_IVAR_$_DynamicObject.ownerID'  # inherited
    assert w['keys'][1]['ivar_offset'] == 36
    y = cls['Yak']
    assert [k['key'] for k in y['keys']] == ['milk', 'hair']  # execution order
    assert [k['ivar_offset'] for k in y['keys']] == [1136, 1140]
    assert all(k['conversion'] == 'numberWithFloat:' for k in y['keys'])
    for name, words in (('disasm_snowsurfaceblock_getsavedict.txt', 15),
                        ('disasm_window_getsavedict.txt', 112),
                        ('disasm_yak_getsavedict.txt', 113)):
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)
    # SSB listing has zero bl/blx (pure accessor)
    ssb_text = (NATIVE / 'disasm_snowsurfaceblock_getsavedict.txt').read_text()
    assert not re.search(r'\bblx?\b', ssb_text), 'SSB must have no calls'
    print('subclass-savedict-keys-b2c-evidence: PASS')

if __name__ == '__main__':
    main()
