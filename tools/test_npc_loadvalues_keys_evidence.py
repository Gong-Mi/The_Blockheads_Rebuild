#!/usr/bin/env python3
"""Static contract for NPC loadValuesFromSaveDict key->writeback pairings."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    r = json.loads((NATIVE / 'npc_loadvalues_keys.json').read_text())
    assert r['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert r['imp'] == '0x00643b20' and r['boundary'] == '0x0064448c'
    assert r['pairing_count'] == 15 and len(r['pairings']) == 15
    ws = json.loads((NATIVE / 'npc_save_keys.json').read_text())
    write_keys = {p['key'] for p in ws['pairings']}
    read_pairs = {p['key']: p for p in r['pairings']}
    # every read key is a write key; the only write key with no read-back is
    # saveTime (derived from world time on save); currentBlockheadIndex shares
    # the CFString object with the write side but lands in a different ivar
    assert write_keys - set(read_pairs) == {'saveTime'}, \
        sorted(write_keys - set(read_pairs))
    assert set(read_pairs) - write_keys == set()
    for k, p in read_pairs.items():
        w = ws['pairings'] if False else next(x for x in ws['pairings'] if x['key'] == k)
        assert p['cfstring_object'] == w['constant_string_object'], k
    # scalar/bool widths follow conversion selector
    for k, p in read_pairs.items():
        conv, wb = p['conversion'], p['writeback']
        if conv == 'floatValue':
            assert wb == 'vstr', (k, wb)
        elif conv == 'intValue' and k != 'currentBlockheadIndex':
            assert wb == 'strh', (k, wb)
        elif conv == 'boolValue':
            assert wb == 'strb', (k, wb)
    assert read_pairs['breed']['conversion'] == 'unsignedIntegerValue'
    assert read_pairs['breed']['writeback'] == 'strh'
    assert read_pairs['tamedClientID']['conversion'] == 'retain'
    assert read_pairs['name']['writeback'] == 'str'
    assert read_pairs['tameCountsByClientID']['writeback'] == 'str'
    assert read_pairs['currentBlockheadIndex']['ivar'] == 'OBJC_IVAR_$_NPC.savedBlockheadIndex'
    assert read_pairs['currentBlockheadIndex']['ivar_offset'] == 136
    assert r['guard_probes'] == {
        'breed': '0x00644044', 'currentBlockheadIndex': '0x00644354',
        'fullness': '0x00643b70', 'layCooldownTimer': '0x00643d70'}
    assert r['dictionary_copy_site'] == '0x006442d4'
    imps = [p['object_for_key_site'] for p in r['pairings']]
    assert len(set(imps)) == 15
    print('npc-loadvalues-keys-evidence: PASS')

if __name__ == '__main__':
    main()
