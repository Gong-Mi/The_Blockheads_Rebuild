#!/usr/bin/env python3
"""Static contract for batch 2c getSaveDict shapes."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

EXPECTED_LISTING_SHA256 = {
    'disasm_snowsurfaceblock_getsavedict.txt': '49c4f6a7c918e0646253e5648231fca4047c58a87bf1d301173a6917a4777021',
    'disasm_window_getsavedict.txt': 'd0f2f6bf383c05ccb83e87fe999240f71c597b2eb6f345a954f7eb24a248fbc1',
    'disasm_yak_getsavedict.txt': '26564d86f4f3da5e769e64b678902e111906f30d3290539aa2960e604eb08a91',
}


def get_body_bytes(text):
    pairs = re.findall(r'^\s+(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s', text, re.MULTILINE)
    return b''.join(bytes.fromhex(w) for _, w in pairs)


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
    for name, expected_sha in EXPECTED_LISTING_SHA256.items():
        t = (NATIVE / name).read_text()
        raw = get_body_bytes(t)
        actual_sha = hashlib.sha256(raw).hexdigest()
        assert actual_sha == expected_sha, f"{name} body sha256 mismatch"

    # Negative control: mutating an instruction must fail
    fake = re.sub(r'(0x00c98ec0\s+)[0-9a-f]{8}', r'\g<1>00000000', (NATIVE / 'disasm_window_getsavedict.txt').read_text())
    assert hashlib.sha256(get_body_bytes(fake)).hexdigest() != EXPECTED_LISTING_SHA256['disasm_window_getsavedict.txt']

    # SSB listing has zero bl/blx (pure accessor)
    ssb_text = (NATIVE / 'disasm_snowsurfaceblock_getsavedict.txt').read_text()
    assert not re.search(r'\bblx?\b', ssb_text), 'SSB must have no calls'
    print('subclass-savedict-keys-b2c-evidence: PASS')

if __name__ == '__main__':
    main()
