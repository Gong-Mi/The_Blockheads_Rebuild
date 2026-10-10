#!/usr/bin/env python3
"""Static contract for the minimal tree getSaveDict own-key pairings."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

EXPECTED_LISTING_SHA256 = {
    'disasm_appletree_getsavedict.txt': 'f543195f63d85796ce4515ab66d66f1b2f4ff822d6876218330bd82bea6b3485',
    'disasm_pinetree_getsavedict.txt': 'fdad9400e8e9298e748262bd9ecb50b9728a7fb842409d7c0240b90375ebf9e5',
    'disasm_gemtree_getsavedict.txt': '56cbb9136a7a8ffa0a5c51fc0d6094e186e836c0be9e2121b47bcc344f709c04',
}


def get_body_bytes(text):
    pairs = re.findall(r'^\s+(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s', text, re.MULTILINE)
    return b''.join(bytes.fromhex(w) for _, w in pairs)


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
    for name, expected_sha in EXPECTED_LISTING_SHA256.items():
        t = (NATIVE / name).read_text()
        assert t.count('# implementation: ') == 1
        raw = get_body_bytes(t)
        actual_sha = hashlib.sha256(raw).hexdigest()
        assert actual_sha == expected_sha, f"{name} body sha256 mismatch"

    # Negative control: mutating an instruction must fail
    fake = re.sub(r'(0x009bd590\s+)[0-9a-f]{8}', r'\g<1>00000000', (NATIVE / 'disasm_appletree_getsavedict.txt').read_text())
    assert hashlib.sha256(get_body_bytes(fake)).hexdigest() != EXPECTED_LISTING_SHA256['disasm_appletree_getsavedict.txt']
    print('tree-savedict-keys-evidence: PASS')

if __name__ == '__main__':
    main()
