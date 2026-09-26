#!/usr/bin/env python3
"""Static contract for batch 2d getSaveDict key pairings."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

EXPECTED_LISTING_SHA256 = {
    'disasm_paintingcico_getsavedict.txt': '610dc77175e62858250aa3bd18c2b0db9ec0267275079cc233a764e4aec67f9d',
    'disasm_normalplant_getsavedict.txt': '6823427ed712b86d5e3489c1b38c739e9613c90cfd11ac4d4bb69ba71e401d64',
    'disasm_glowblock_getsavedict.txt': '34ec60de9edc1cb2f3c7335af18126622eab6691e69d9b79ecefe723abee41cd',
    'disasm_gatherblock_getsavedict.txt': '261d82222931736aa1141617d5214b9b78c4fc643f55c4b3726d71ece79bd7da',
}


def get_body_bytes(text):
    pairs = re.findall(r'^\s+(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s', text, re.MULTILINE)
    return b''.join(bytes.fromhex(w) for _, w in pairs)


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
    for name, expected_sha in EXPECTED_LISTING_SHA256.items():
        t = (NATIVE / name).read_text()
        raw = get_body_bytes(t)
        actual_sha = hashlib.sha256(raw).hexdigest()
        assert actual_sha == expected_sha, f"{name} body sha256 mismatch"

    # Negative control: mutating an instruction must fail
    fake = re.sub(r'(0x00869800\s+)[0-9a-f]{8}', r'\g<1>00000000', (NATIVE / 'disasm_gatherblock_getsavedict.txt').read_text())
    assert hashlib.sha256(get_body_bytes(fake)).hexdigest() != EXPECTED_LISTING_SHA256['disasm_gatherblock_getsavedict.txt']
    print('subclass-savedict-keys-b2d-evidence: PASS')

if __name__ == '__main__':
    main()
