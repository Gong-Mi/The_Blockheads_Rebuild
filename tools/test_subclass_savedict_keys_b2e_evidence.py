#!/usr/bin/env python3
"""Static contract for batch 2e getSaveDict key pairings."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    r = json.loads((NATIVE / 'subclass_savedict_keys_b2e.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    cls = {c['class']: c for c in r['classes']}
    assert list(cls) == ['Tutorial', 'BlockheadCraftableItemObject', 'Ladder', 'TradePortal']
    tu = cls['Tutorial']
    assert tu['style'] == 'fresh_dictionary' and tu['code_words'] == 146
    assert [k['key'] for k in tu['keys']] == ['state', 'impromptuNightState',
                                              'wrongToolHasBeenDisplayed']
    assert [k['ivar_offset'] for k in tu['keys']] == [12, 16, 20]
    assert tu['keys'][2]['conversion'] == 'numberWithBool:'
    bi = cls['BlockheadCraftableItemObject']
    assert [k['key'] for k in bi['keys']] == ['name', 'skinOptions', 'craftableObjectType']
    assert bi['keys'][0]['conversion'] == 'direct_object'
    assert bi['keys'][1]['conversion'] == 'dataWithBytes:length:'
    assert bi['keys'][1]['pod_length'] == 20
    assert bi['keys'][2]['value_constant'] == 1
    la = cls['Ladder']
    assert [k['key'] for k in la['keys']] == ['itemType', 'paintColor', 'ownerID']
    assert la['keys'][1]['conversion'] == 'numberWithUnsignedInt:'
    assert la['keys'][2]['ivar'] == 'OBJC_IVAR_$_DynamicObject.ownerID'  # inherited
    tp = cls['TradePortal']
    assert [k['key'] for k in tp['keys']] == ['localPriceOffsets', 'level', 'lightDict']
    assert tp['keys'][2]['conversion'] == 'nested_getSaveDict'
    assert tp['keys'][2]['ivar_offset'] == 100
    for name, words in (('disasm_tutorial_getsavedict.txt', 146),
                        ('disasm_bcico_getsavedict.txt', 150),
                        ('disasm_ladder_getsavedict.txt', 155),
                        ('disasm_tradeportal_getsavedict.txt', 157)):
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)
    print('subclass-savedict-keys-b2e-evidence: PASS')

if __name__ == '__main__':
    main()
