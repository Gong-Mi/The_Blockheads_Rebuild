#!/usr/bin/env python3
"""Static contract for batch 2g getSaveDict key pairings."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

EXPECTED_LISTING_SHA256 = {
    'disasm_rail_getsavedict.txt': '4561dd630f685e37aa3855f23d7dde02dc4858f1116094d34367c572037e8dea',
    'disasm_kelpplant_getsavedict.txt': 'e6aca745958261705658addbcdda671b27ef9f738c5d540e4162e9a93f276baa',
    'disasm_vineplant_getsavedict.txt': '721be285cbd7360731b72d5cb41474b242d7f42391bb89d70ed9ad539b3752ee',
    'disasm_egg_getsavedict.txt': '5b5c0a65936c297f513e72984f02210ac92b4ad1cd1559008f4f46c3bf2ca61f',
}


def get_body_bytes(text):
    pairs = re.findall(r'^\s+(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s', text, re.MULTILINE)
    return b''.join(bytes.fromhex(w) for _, w in pairs)


def main():
    r = json.loads((NATIVE / 'subclass_savedict_keys_b2g.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    cls = {c['class']: c for c in r['classes']}
    assert list(cls) == ['Rail', 'KelpPlant', 'VinePlant', 'Egg']
    rl = cls['Rail']
    assert [k['key'] for k in rl['keys']] == ['itemType', 'configuration', 'ownedByStation']
    assert rl['keys'][2]['conversion'] == 'numberWithBool:' and rl['keys'][2]['ivar_offset'] == 65
    assert rl['keys'][1]['ivar'] == 'OBJC_IVAR_$_Rail.currentConfiguration'
    kp, vp = cls['KelpPlant'], cls['VinePlant']
    assert [k['key'] for k in kp['keys']] == ['numberOfOccupiedTilesAbove', 'growthTimer', 'availableFood']
    assert [k['key'] for k in vp['keys']] == ['numberOfOccupiedTilesBelow', 'growthTimer', 'availableFood']
    assert kp['keys'][0]['ivar_offset'] == 200 and vp['keys'][0]['ivar_offset'] == 180
    assert kp['keys'][2]['ivar_offset'] == 180 and vp['keys'][2]['ivar_offset'] == 100
    assert all(k['conversion'] == 'numberWithFloat:' for k in kp['keys'][1:])
    assert all(k['conversion'] == 'numberWithFloat:' for k in vp['keys'][1:])
    eg = cls['Egg']
    assert [k['key'] for k in eg['keys']] == ['hatchTimer', 'saveTime', 'genesDict']  # exec order
    st = eg['keys'][1]
    assert st['conversion'] == 'world_time_derived'
    assert st['value_ivar'] == 'OBJC_IVAR_$_DynamicObject.world' and st['value_ivar_offset'] == 4
    assert eg['keys'][0]['ivar_offset'] == 64 and eg['keys'][2]['ivar_offset'] == 56
    assert eg['keys'][2]['conversion'] == 'direct_object'
    for name, expected_sha in EXPECTED_LISTING_SHA256.items():
        t = (NATIVE / name).read_text()
        raw = get_body_bytes(t)
        actual_sha = hashlib.sha256(raw).hexdigest()
        assert actual_sha == expected_sha, f"{name} body sha256 mismatch"

    # Negative control: mutating an instruction must fail
    fake = re.sub(r'(0x0077b180\s+)[0-9a-f]{8}', r'\g<1>00000000', (NATIVE / 'disasm_rail_getsavedict.txt').read_text())
    assert hashlib.sha256(get_body_bytes(fake)).hexdigest() != EXPECTED_LISTING_SHA256['disasm_rail_getsavedict.txt']
    print('subclass-savedict-keys-b2g-evidence: PASS')

if __name__ == '__main__':
    main()
