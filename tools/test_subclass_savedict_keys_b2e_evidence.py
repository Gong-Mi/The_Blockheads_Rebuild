#!/usr/bin/env python3
"""Static contract for batch 2e getSaveDict key pairings."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

EXPECTED_LISTING_SHA256 = {
    'disasm_tutorial_getsavedict.txt': 'f045d18a6f6554eb6309163de868216974b0844ad74f6ad80caf034e9542342d',
    'disasm_bcico_getsavedict.txt': '14d1ba23269ab1e9a87d02d8f3846cac4a26b22ca978c650441aaaab723f9fbc',
    'disasm_ladder_getsavedict.txt': 'f6337c8c505c5ef34241acbcc81087c9d50d41cc24b49a58f156de9e0aa44fe1',
    'disasm_tradeportal_getsavedict.txt': '66b3d45bd61f7edeac3bc5164a38a2d90a840e857b2cb677941a359984e823d2',
}


def get_body_bytes(text):
    pairs = re.findall(r'^\s+(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s', text, re.MULTILINE)
    return b''.join(bytes.fromhex(w) for _, w in pairs)


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
    for name, expected_sha in EXPECTED_LISTING_SHA256.items():
        t = (NATIVE / name).read_text()
        raw = get_body_bytes(t)
        actual_sha = hashlib.sha256(raw).hexdigest()
        assert actual_sha == expected_sha, f"{name} body sha256 mismatch"

    # Negative control: mutating an instruction must fail
    fake = re.sub(r'(0x00aae3d0\s+)[0-9a-f]{8}', r'\g<1>00000000', (NATIVE / 'disasm_ladder_getsavedict.txt').read_text())
    assert hashlib.sha256(get_body_bytes(fake)).hexdigest() != EXPECTED_LISTING_SHA256['disasm_ladder_getsavedict.txt']
    print('subclass-savedict-keys-b2e-evidence: PASS')

if __name__ == '__main__':
    main()
