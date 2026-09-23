#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-2j save-key evidence.

Re-runs tools/recover_subclass_savedict_keys_b2j.py against the pinned ELF
and asserts byte-identical JSON with the checked-in
reconstruction/reverse-v3/native/subclass_savedict_keys_b2j.json, plus
content-level assertions (class/key sets, conversions, TradingPost
saveData==selector semantics, Torch halfword loads, FireObject float lanes).
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'subclass_savedict_keys_b2j.json'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if not ELF.exists():
        print(f'ELF missing: {ELF}')
        sys.exit(1)
    r = subprocess.run(
        [sys.executable, str(ROOT / 'tools/recover_subclass_savedict_keys_b2j.py'),
         str(ELF), '--check'],
        capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout + r.stderr)
        raise SystemExit('stale subclass_savedict_keys_b2j.json')
    print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA, 'elf sha drift'
    assert d['method'] == 'getSaveDict key pairings (batch 2j)'
    classes = {c['class']: c for c in d['classes']}
    assert set(classes) == {'Torch', 'TradingPost', 'FireObject'}

    t = classes['Torch']
    assert t['imp'] == '0x004b65b8' and t['boundary'] == '0x004b69e0'
    assert t['code_words'] == 266
    tk = {k['key']: k for k in t['keys']}
    assert set(tk) == {'itemType', 'dataA', 'dataB', 'connectionType',
                       'lightDict', 'ownerID'}
    for k in ('itemType', 'dataA', 'dataB', 'connectionType'):
        assert tk[k]['conversion'] == 'numberWithInt:', f'{k} conv'
        assert tk[k]['ivar'] == f'OBJC_IVAR_$_Torch.{k}'
    assert tk['itemType']['ivar_offset'] == 64
    assert tk['dataA']['ivar_offset'] == 80 and tk['dataB']['ivar_offset'] == 82
    assert tk['connectionType']['ivar_offset'] == 60
    assert tk['lightDict']['conversion'] == 'direct_object'
    assert tk['lightDict']['ivar'] == 'OBJC_IVAR_$_Torch.light'
    assert tk['lightDict']['ivar_offset'] == 56
    assert tk['ownerID']['conversion'] == 'direct_object'
    assert tk['ownerID']['ivar'] == 'OBJC_IVAR_$_DynamicObject.ownerID'
    assert tk['ownerID']['ivar_offset'] == 36
    assert 'dataA_ldrh@0x004b6784' in t['site_gates']
    assert 'dataB_ldrh@0x004b67e4' in t['site_gates']
    assert 'second_getsavedict_site@0x004b660c' in t['site_gates']
    assert 'ownerID_guard_beq@0x004b6928' in t['site_gates']
    assert 'light_guard_beq@0x004b68bc' in t['site_gates']

    tp = classes['TradingPost']
    assert tp['imp'] == '0x005e6b08' and tp['boundary'] == '0x005e7024'
    assert tp['code_words'] == 327
    tpk = {k['key']: k for k in tp['keys']}
    assert set(tpk) == {'sellerClientName', 'coinCount', 'priceTier', 'sellSlot'}
    assert tpk['sellerClientName']['conversion'] == 'direct_object'
    assert tpk['sellerClientName']['ivar_offset'] == 112
    assert tpk['coinCount']['conversion'] == 'numberWithInt:'
    assert tpk['coinCount']['ivar_offset'] == 104
    assert tpk['coinCount']['conversion_site'] == '0x005e6f38'
    assert tpk['coinCount']['set_object_site'] == '0x005e6f5c'
    assert tpk['priceTier']['conversion'] == 'numberWithInt:'
    assert tpk['priceTier']['ivar_offset'] == 108
    assert tpk['priceTier']['conversion_site'] == '0x005e6f98'
    assert tpk['priceTier']['set_object_site'] == '0x005e6fbc'
    assert tpk['sellSlot']['conversion'] == 'direct_object'
    assert tpk['sellSlot']['ivar_offset'] == 100
    assert tpk['sellSlot']['set_object_site'] == '0x005e6efc'
    gates = set(tp['site_gates'])
    assert 'itemtype_cmp_0xb@0x005e6d68' in gates
    assert 'itemtype_beq@0x005e6d6c' in gates
    assert 'savedata_msg_site@0x005e6db4' in gates
    assert 'addobject_site@0x005e6dd4' in gates
    assert 'enumerate_site@0x005e6cb8' in gates
    assert 'seller_guard_beq@0x005e6b90' in gates

    fo = classes['FireObject']
    assert fo['imp'] == '0x0067501c' and fo['boundary'] == '0x006753ec'
    assert fo['code_words'] == 244
    fok = {k['key']: k for k in fo['keys']}
    assert set(fok) == {'burnTimer', 'spreadTimer_0', 'spreadTimer_1',
                        'spreadTimer_2', 'spreadTimer_3', 'lightDict'}
    for k in fok.values():
        if k['key'] == 'lightDict':
            continue
        assert k['conversion'] == 'numberWithFloat:', f'{k} conv'
    assert fok['burnTimer']['ivar'] == 'OBJC_IVAR_$_FireObject.burnTimer'
    assert fok['burnTimer']['ivar_offset'] == 56
    for i in range(4):
        assert fok[f'spreadTimer_{i}']['ivar'] == \
            'OBJC_IVAR_$_FireObject.spreadTimers'
        assert fok[f'spreadTimer_{i}']['ivar_offset'] == 60
    assert fok['lightDict']['conversion'] == 'direct_object'
    assert fok['lightDict']['ivar'] == 'OBJC_IVAR_$_FireObject.light'
    assert fok['lightDict']['ivar_offset'] == 76
    assert 'burn_vldr@0x0067513c' in fo['site_gates']
    for i, site in enumerate(('0x006751bc', '0x0067521c',
                              '0x0067527c', '0x006752dc')):
        assert f'spread_vldr_{i}@{site}' in fo['site_gates']
    assert 'light_guard_beq@0x00675354' in fo['site_gates']
    assert 'second_getsavedict_site@0x00675070' in fo['site_gates']

    print('b2j evidence: PASS')


if __name__ == '__main__':
    main()
