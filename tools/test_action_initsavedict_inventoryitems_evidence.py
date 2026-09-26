#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-b3d Action init evidence.

Host (pinned ELF present): recovery tool `--check` (byte-identical JSON) and
`--self-test` (all mutations must be caught). CI (ELF absent): static content
assertions + listing word count.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'action_initsavedict_inventoryitems.json'
RECOVER = ROOT / 'tools/recover_action_initsavedict_inventoryitems.py'
LISTING = NATIVE / 'disasm_action_initsavedict_inventoryitems.txt'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if ELF.exists():
        for args, label in ((['--check'], 'stale action_initsavedict_inventoryitems.json'),
                            (['--self-test'], 'b3d negative controls failed')):
            r = subprocess.run([sys.executable, str(RECOVER), str(ELF)] + args,
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(r.stdout + r.stderr)
                raise SystemExit(label)
            print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA and d['batch'] == 'b3d'
    assert d['class'] == 'Action'
    assert (d['imp'], d['boundary'], d['code_words']) == \
        ('0x00735198', '0x00735e54', 815)
    assert d['selector'] == 'initWithSaveDict:inventoryItems:'
    assert d['super_init']['selector'] == 'init'
    assert d['super_init']['superref_slot'] == '0x00e8bd04'
    assert d['super_init']['class_object'] == 'OBJC_CLASS_$_Action'

    chains = {c['key']: c for c in d['keys']}
    assert set(chains) == {'inProgress', 'isAI', 'goalTilePos.x', 'goalTilePos.y',
                           'interactionItemIndex', 'interactionItemSubIndex',
                           'goalInteraction', 'pathType', 'interactionObjectID',
                           'craftCountOrExtraData', 'inventoryChange',
                           'interactionTestResult'}, set(chains)
    expect = {
        'inProgress': ('boolValue', 'byte_store', 4, 4),
        'isAI': ('boolValue', 'byte_store', 6, 6),
        'goalTilePos.x': ('intValue', 'word_store', 8, 8),
        'goalTilePos.y': ('intValue', 'word_store_pair', 8, 12),
        'interactionItemIndex': ('intValue', 'halfword_store', 20, 20),
        'interactionItemSubIndex': ('intValue', 'halfword_store', 22, 22),
        'goalInteraction': ('intValue', 'word_store', 24, 24),
        'pathType': ('intValue', 'word_store', 28, 28),
        'interactionObjectID': ('unsignedLongValue', 'word_store_hi_zero', 32, 32),
        'craftCountOrExtraData': ('intValue', 'halfword_store', 44, 44),
        'inventoryChange': ('retain', 'word_store', 64, 64),
        'interactionTestResult': ('getBytes:length:', 'blob_store', 52, 52),
    }
    for key, (conv, kind, off, store_off) in expect.items():
        c = chains[key]
        assert (c['conversion'], c['store_kind'], c['ivar_offset'],
                c['store_offset']) == (conv, kind, off, store_off), key
        assert c['ivar'] == f'OBJC_IVAR_$_Action.{key.split(".")[0]}', key
        assert c['cfstring_object'].startswith('0x00f8cc') or \
            c['cfstring_object'].startswith('0x00f8cd'), key
    assert chains['goalTilePos.y']['objectforkey_site'] == '0x00735420'
    assert chains['interactionObjectID']['conversion_site'] == '0x007359b4'

    assert [k['key'] for k in d['local_keys']] == ['interactionItemType',
                                                   'craftableObjectType']
    assert [k['key'] for k in d['object_keys']] == ['craftableItemObject']
    assert d['object_keys'][0]['nil_cmp_site'] == '0x007359fc'

    walk = d['inventory_walk']
    assert 'interactionItemIndex@20 > 0' in walk['entry_gate']
    assert walk['call_sites'][0].startswith('0x735590')
    assert walk['type_mismatch_reset']['equal_branch'] == '0x735824 (keep)'
    assert set(walk['type_mismatch_reset']['mismatch_sets']) == \
        {'interactionItem@16', 'interactionItemIndex@20',
         'interactionItemSubIndex@22'}

    consts = d['constants']
    assert '1.0f' in consts['animationTimer@68']
    assert 'high word zeroed' in consts['interactionObjectID@32']
    assert '12' in consts['interactionTestResult@52']

    disp = {c['craftableObjectType']: c for c in d['craftable_dispatch']}
    assert set(disp) == {1, 2, None}
    assert disp[1]['class_object'] == 'OBJC_CLASS_$_BlockheadCraftableItemObject'
    assert disp[2]['class_object'] == 'OBJC_CLASS_$_PaintingCraftableItemObject'
    assert disp[None]['class_object'] == 'OBJC_CLASS_$_CraftableItemObject'
    assert [disp[t]['instance_size'] for t in (1, 2, None)] == [152, 136, 128]
    assert disp[1]['classref_slot'] == '0x00e8a544'

    assert d['retain_sites'] == {'interactionItem@16': '0x7358ec',
                                 'inventoryChange@64': '0x735d10'}
    assert d['msgSend_veneer']['veneer_slot'] == '0x0105fb18'
    assert d['msgSend_veneer']['veneer_target'] == 'objc_msgSend'
    assert len(d['pool_keys']) == 15
    assert d['save_side']['source'] == 'subclass_savedict_keys_b2o.json'
    assert len(d['save_side']['keys']) == 14
    assert d['save_side']['write_only'] == []
    assert d['save_side']['read_only'] == ['craftableObjectType']

    t = LISTING.read_text()
    n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
    assert n == 815, n
    assert '# -[Action initWithSaveDict:inventoryItems:]' in t

    print('b3d evidence: PASS')


if __name__ == '__main__':
    main()
