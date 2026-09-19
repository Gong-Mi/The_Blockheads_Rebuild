#!/usr/bin/env python3
"""Static contract for batch 2f getSaveDict key pairings (template family)."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

EXPECTED_LISTING_SHA256 = {
    'disasm_column_getsavedict.txt': '7a18973e5926677afbffc540e090fc2f8401ed229d92f37c9058ca11fe7f4d52',
    'disasm_stairs_getsavedict.txt': '5d1be82ba5739d7386d398238e461972dc2b32ca38bc0458d0ba41166c8c5f47',
    'disasm_door_getsavedict.txt': '82da0d225cb14a25e4b88d6b9b8cd69a7ddfe391e78106ede0b9bf859af61113',
    'disasm_wire_getsavedict.txt': '3416dc04b119eddc49f46ced64454e3b3708eeb251636017107a68ffe7e478ee',
}


def get_body_bytes(text):
    pairs = re.findall(r'^\s+(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s', text, re.MULTILINE)
    return b''.join(bytes.fromhex(w) for _, w in pairs)


def main():
    r = json.loads((NATIVE / 'subclass_savedict_keys_b2f.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    cls = {c['class']: c for c in r['classes']}
    assert list(cls) == ['Column', 'Stairs', 'Door', 'Wire']
    for c in cls.values():
        assert c['style'] == 'super_plus_own_keys'
        assert c['keys'][-1]['key'] == 'ownerID'
        assert c['keys'][-1]['ivar'] == 'OBJC_IVAR_$_DynamicObject.ownerID'
        assert c['keys'][-1]['ivar_offset'] == 36
        assert c['keys'][-1]['conversion'] == 'direct_object'
    col, st, dr, wi = cls['Column'], cls['Stairs'], cls['Door'], cls['Wire']
    assert [k['key'] for k in col['keys']] == ['itemType', 'configuration', 'paintColor', 'ownerID']
    assert col['keys'][0]['ivar'] == 'OBJC_IVAR_$_Column.itemType' and col['keys'][0]['ivar_offset'] == 56
    assert col['keys'][1]['ivar'] == 'OBJC_IVAR_$_Column.currentConfiguration'
    assert col['keys'][2]['conversion'] == 'numberWithUnsignedInt:' and col['keys'][2]['ivar_offset'] == 60
    assert [k['key'] for k in st['keys']] == ['itemType', 'configuration', 'paintColor', 'ownerID']
    assert st['keys'][1]['ivar_offset'] == 60 and st['keys'][2]['ivar_offset'] == 64
    assert [k['key'] for k in dr['keys']] == ['itemType', 'blocked', 'ironPlaceClientID', 'ownerID']
    assert dr['keys'][0]['ivar_offset'] == 64 and dr['keys'][1]['ivar_offset'] == 68
    assert dr['keys'][2]['conversion'] == 'direct_object' and dr['keys'][2]['ivar_offset'] == 72
    assert [k['key'] for k in wi['keys']] == ['itemType', 'configuration', 'solidConfiguration', 'ownerID']
    assert wi['keys'][2]['ivar'] == 'OBJC_IVAR_$_Wire.currentSolidConfiguration'
    assert wi['keys'][2]['ivar_offset'] == 64
    for name, expected_sha in EXPECTED_LISTING_SHA256.items():
        t = (NATIVE / name).read_text()
        raw = get_body_bytes(t)
        actual_sha = hashlib.sha256(raw).hexdigest()
        assert actual_sha == expected_sha, f"{name} body sha256 mismatch"

    # Negative control: mutating an instruction must fail
    fake = re.sub(r'(0x00769ee0\s+)[0-9a-f]{8}', r'\g<1>00000000', (NATIVE / 'disasm_door_getsavedict.txt').read_text())
    assert hashlib.sha256(get_body_bytes(fake)).hexdigest() != EXPECTED_LISTING_SHA256['disasm_door_getsavedict.txt']
    print('subclass-savedict-keys-b2f-evidence: PASS')

if __name__ == '__main__':
    main()
