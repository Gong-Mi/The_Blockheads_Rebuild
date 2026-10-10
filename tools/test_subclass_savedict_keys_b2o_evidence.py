#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-2o save-key evidence.

On a host with the pinned ELF present, re-runs the recovery script and
asserts byte-identical JSON; on CI (ELF absent) falls back to static
content assertions plus listing word counts (same shape as b2i..b2n).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'subclass_savedict_keys_b2o.json'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if ELF.exists():
        r = subprocess.run(
            [sys.executable, str(ROOT / 'tools/recover_subclass_savedict_keys_b2o.py'),
             str(ELF), '--check'],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('stale subclass_savedict_keys_b2o.json')
        print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA, 'elf sha drift'
    assert d['method'] == 'getSaveDict key pairings (batch 2o)'
    cls = {c['class']: c for c in d['classes']}
    assert set(cls) == {'Action', 'Tree'}

    act = cls['Action']
    assert act['imp'] == '0x00735e54' and act['boundary'] == '0x0073664c'
    assert act['code_words'] == 510
    assert act['style'] == 'own_dictionary_no_super'
    ak = {k['key']: k for k in act['keys']}
    assert set(ak) == {'inProgress', 'isAI', 'goalTilePos.x', 'goalTilePos.y',
                      'interactionItemIndex', 'interactionItemSubIndex',
                      'interactionItemType', 'goalInteraction', 'pathType',
                      'interactionObjectID', 'inventoryChange',
                      'craftableItemObject', 'craftCountOrExtraData',
                      'interactionTestResult'}
    assert len(ak) == 14
    for name, off, conv in (('inProgress', 4, 'numberWithBool:'),
                            ('isAI', 6, 'numberWithBool:'),
                            ('goalInteraction', 24, 'numberWithInt:'),
                            ('pathType', 28, 'numberWithInt:'),
                            ('interactionItemIndex', 20, 'numberWithInt:'),
                            ('interactionItemSubIndex', 22, 'numberWithInt:'),
                            ('interactionObjectID', 32, 'numberWithUnsignedLong:'),
                            ('craftCountOrExtraData', 44, 'numberWithUnsignedInt:')):
        assert ak[name]['conversion'] == conv, name
        assert ak[name]['ivar_offset'] == off, name
    assert ak['goalTilePos.x']['ivar'] == 'OBJC_IVAR_$_Action.goalTilePos'
    assert ak['goalTilePos.x']['ivar_offset'] == 8
    assert ak['goalTilePos.y']['ivar_offset'] == 8
    assert ak['interactionItemType']['value_source'] == 'computed_selector'
    assert ak['interactionItemType']['ivar'] == 'OBJC_IVAR_$_Action.interactionItem'
    assert ak['inventoryChange']['conversion'] == 'direct_object'
    assert ak['inventoryChange']['ivar_offset'] == 64
    assert ak['craftableItemObject']['conversion'] == 'direct_object'
    assert ak['craftableItemObject']['value_source'] == 'nested_getSaveDict'
    assert ak['craftableItemObject']['ivar_offset'] == 40
    assert ak['craftCountOrExtraData']['value_source'] == 'signed_halfword'
    itr = ak['interactionTestResult']
    assert itr['conversion'] == 'dataWithBytes:length:'
    assert itr['value_source'] == 'raw_buffer'
    assert itr['raw_length'] == 0xc
    assert itr['ivar_offset'] == 52
    gates = set(act['site_gates'])
    for g in ('dictionary_call@0x00735ee0',
              'inprogress_ldrsb@0x00735f10',
              'itemtype_msg@0x0073619c',
              'inventory_guard_beq@0x0073632c',
              'nested_getsavedict_msg@0x007363d0',
              'nested_guard_beq@0x007363e4',
              'craftraw_len_movw_0xc@0x0073644c',
              'craftcount_ldrsh@0x007364cc'):
        assert g in gates, g

    tr = cls['Tree']
    assert tr['imp'] == '0x004c3cac' and tr['boundary'] == '0x004c4974'
    assert tr['code_words'] == 818
    assert tr['style'] == 'super_plus_own_keys'
    tk = {k['key']: k for k in tr['keys']}
    assert set(tk) == {'height', 'saveTime', 'treeSeasonOffset', 'age',
                      'dead', 'timeDied', 'removeCheckCount', 'treeFruit',
                      'maxHeightGene', 'growthRateGene',
                      'maxHeightReached', 'growthCounter', 'growthRate',
                      'maxHeight', 'maxAge'}
    assert len(tk) == 15
    sv = tk['saveTime']
    assert sv['conversion'] == 'numberWithDouble:'
    assert sv['value_source'] == 'world_selector'
    td = tk['timeDied']
    assert td['conversion'] == 'numberWithDouble:'
    assert td['ivar'] == 'OBJC_IVAR_$_Tree.timeDied'
    assert td['ivar_offset'] == 112
    tf = tk['treeFruit']
    assert tf['conversion'] == 'direct_object'
    assert tf['value_source'] == 'fruit_dict_array'
    assert tf['set_object_site'] == '0x004c44a4'
    for name, gated in (('maxHeightGene', True), ('growthRateGene', True),
                       ('maxHeightReached', True), ('growthCounter', True),
                       ('growthRate', True), ('maxHeight', True),
                       ('maxAge', True)):
        assert tk[name].get('gated_by') == 'isStaticTree==false', name
    tgate = set(tr['site_gates'])
    for g in ('super_site@0x004c3d00',
              'age_vldr_s2@0x004c4010',
              'dead_ldrb@0x004c4070',
              'timedied_vldr_d0@0x004c40d0',
              'worldtime_msg@0x004c3f4c',
              'fruit_array_create@0x004c4190',
              'fruit_dict_create@0x004c42bc',
              'fruit_pos_x_ldr@0x004c42f4',
              'fruit_pos_y_ldr4@0x004c4368',
              'fruit_hcfb_ldrb8@0x004c43dc',
              'fruit_addobject@0x004c4440',
              'isstatictree_msg@0x004c44b8',
              'isstatictree_bne@0x004c44c4',
              'gene_maxheight_ldrh@0x004c45f0',
              'gene_growthrate_ldrh@0x004c4674',
              'maxage_vldr@0x004c4854'):
        assert g in tgate, g

    for name, words in (('disasm_action_getsavedict.txt', 510),
                        ('disasm_tree_getsavedict.txt', 818)):
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
        assert n == words, (name, n)

    print('b2o evidence: PASS')


if __name__ == '__main__':
    main()
