#!/usr/bin/env python3
"""Static contract for batch 2b item subclass getSaveDict pairings."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

EXPECTED_LISTING_SHA256 = {
    'disasm_bed_getsavedict.txt': '2000176fcad9e1f75fbfb7573706e1149dda476d8925e01369566de9bb080c9f',
    'disasm_trainstation_getsavedict.txt': '958bd2b14803a5dc686470623917ca8fd9eed72eb6116cc598899cc73c4c8bce',
    'disasm_craftableitemobject_getsavedict.txt': 'e8b45b74c0d5589b152dafd078c92c30788bbf333bc54939d24eb658043abb27',
}


def get_body_bytes(text):
    pairs = re.findall(r'^\s+(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s', text, re.MULTILINE)
    return b''.join(bytes.fromhex(w) for _, w in pairs)


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
    for name, expected_sha in EXPECTED_LISTING_SHA256.items():
        t = (NATIVE / name).read_text()
        raw = get_body_bytes(t)
        actual_sha = hashlib.sha256(raw).hexdigest()
        assert actual_sha == expected_sha, f"{name} body sha256 mismatch"

    # Negative control: mutating an instruction must fail
    fake = re.sub(r'(0x00d41120\s+)[0-9a-f]{8}', r'\g<1>00000000', (NATIVE / 'disasm_bed_getsavedict.txt').read_text())
    assert hashlib.sha256(get_body_bytes(fake)).hexdigest() != EXPECTED_LISTING_SHA256['disasm_bed_getsavedict.txt']
    print('item-savedict-keys-b2b-evidence: PASS')

if __name__ == '__main__':
    main()
