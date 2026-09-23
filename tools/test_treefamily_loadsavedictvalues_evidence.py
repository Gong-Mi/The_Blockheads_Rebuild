#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-b3b tree-family load evidence.

On a host with the pinned ELF present: re-runs the recovery script in
`--check` mode (byte-identical JSON) and in `--self-test` mode (every
mutation must be detected). On CI (ELF absent) it falls back to static
content assertions plus listing word counts, same shape as b2i..b2p/b3a.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'treefamily_loadsavedictvalues.json'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
RECOVER = ROOT / 'tools/recover_treefamily_loadsavedictvalues.py'
LISTINGS = {
    'Plant': ('disasm_plant_loadsavedictvalues.txt', 332),
    'GemTree': ('disasm_gemtree_loadsavedictvalues.txt', 99),
    'CactusTree': ('disasm_cactustree_loadsavedictvalues.txt', 157),
    'CoconutTree': ('disasm_coconuttree_loadsavedictvalues.txt', 29),
}


def main():
    if ELF.exists():
        r = subprocess.run([sys.executable, str(RECOVER), str(ELF), '--check'],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('stale treefamily_loadsavedictvalues.json')
        print(r.stdout.strip())
        s = subprocess.run([sys.executable, str(RECOVER), str(ELF), '--self-test'],
                           capture_output=True, text=True)
        if s.returncode != 0:
            print(s.stdout + s.stderr)
            raise SystemExit('b3b negative controls failed')
        print(s.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA, 'elf sha drift'
    assert d['batch'] == 'b3b'
    assert 'loadSaveDictValues' in d['method']
    by = {c['class']: c for c in d['classes']}
    assert set(by) == set(LISTINGS), set(by)

    # ---- per-class method identity + key chains
    expect = {
        'Plant': ('0x009554a0', '0x009559d0', 332, 'own_keys_no_super'),
        'GemTree': ('0x005293ec', '0x00529578', 99, 'own_keys_then_super'),
        'CactusTree': ('0x00b534b4', '0x00b53728', 157, 'super_then_own_keys'),
        'CoconutTree': ('0x00a99a40', '0x00a99ab4', 29, 'super_forward_only'),
    }
    for cls, (imp, boundary, words, style) in expect.items():
        c = by[cls]
        assert (c['imp'], c['boundary'], c['code_words'], c['style']) == \
            (imp, boundary, words, style), cls
        assert c['selector'] == 'loadSaveDictValues:'

    plant = {k['key']: k for k in by['Plant']['keys']}
    assert set(plant) == {'seasonOffset', 'age', 'gatherProgress',
                          'hasFloweredThisSeason', 'flowering', 'frozen',
                          'maxAgeGene', 'growthRateGene'}, set(plant)
    for key, conv, kind, off in (
            ('seasonOffset', 'intValue', 'word_store', 68),
            ('age', 'floatValue', 'float_store', 72),
            ('gatherProgress', 'intValue', 'word_store', 80),
            ('hasFloweredThisSeason', 'boolValue', 'byte_store', 84),
            ('flowering', 'boolValue', 'byte_store', 85),
            ('frozen', 'boolValue', 'byte_store', 76),
            ('maxAgeGene', 'intValue', 'halfword_store', 54),
            ('growthRateGene', 'intValue', 'halfword_store', 56)):
        entry = plant[key]
        assert entry['conversion'] == conv, key
        assert entry['store_kind'] == kind, key
        assert entry['ivar_offset'] == off, key
        assert entry['ivar'] == f'OBJC_IVAR_$_Plant.{key}', key
    assert plant['seasonOffset']['cfstring_object'] == '0x00f954f8'
    assert plant['maxAgeGene']['cfstring_object'] == '0x00f95558'

    gem = {k['key']: k for k in by['GemTree']['keys']}
    assert set(gem) == {'gemTreeType', 'fruitYear'}
    assert (gem['gemTreeType']['conversion'], gem['gemTreeType']['ivar_offset'],
            gem['gemTreeType']['store_kind']) == ('intValue', 136, 'word_store')
    assert (gem['fruitYear']['conversion'], gem['fruitYear']['ivar_offset'],
            gem['fruitYear']['store_kind']) == ('intValue', 140, 'word_store')

    cac = {k['key']: k for k in by['CactusTree']['keys']}
    assert set(cac) == {'splitHeightA', 'splitHeightB', 'splitDirection',
                        'availableFood'}
    assert (cac['splitHeightA']['conversion'], cac['splitHeightA']['ivar_offset'],
            cac['splitHeightA']['store_kind']) == ('intValue', 136, 'word_store')
    assert (cac['splitHeightB']['conversion'], cac['splitHeightB']['ivar_offset'],
            cac['splitHeightB']['store_kind']) == ('intValue', 140, 'word_store')
    assert (cac['splitDirection']['conversion'],
            cac['splitDirection']['ivar_offset'],
            cac['splitDirection']['store_kind']) == ('boolValue', 144,
                                                     'byte_store')
    assert (cac['availableFood']['conversion'],
            cac['availableFood']['ivar_offset'],
            cac['availableFood']['store_kind']) == ('floatValue', 148,
                                                    'float_store')
    assert by['CoconutTree']['keys'] == []
    assert by['CoconutTree']['pool_keys'] == []

    # ---- super-forward contract + ordering
    assert by['Plant']['super_forward'] is None
    assert by['Plant']['own_keys_order'] == 'own_keys_no_super'
    assert by['GemTree']['own_keys_order'] == 'own_then_super'
    assert by['CactusTree']['own_keys_order'] == 'super_then_own'
    assert by['CoconutTree']['own_keys_order'] == 'super_only'
    for cls, slot, obj in (('GemTree', '0x00e8bc54', 'OBJC_CLASS_$_GemTree'),
                           ('CactusTree', '0x00e8bea8', 'OBJC_CLASS_$_CactusTree'),
                           ('CoconutTree', '0x00e8be50', 'OBJC_CLASS_$_CoconutTree')):
        sf = by[cls]['super_forward']
        assert sf['dispatch'] == 'objc_msgSendSuper2', cls
        assert sf['selector'] == 'loadSaveDictValues:', cls
        assert sf['superref_slot'] == slot, cls
        assert sf['class_object'] == obj, cls
        assert sf['runtime_superclass'] == 'Tree', cls
        assert sf['got_slot'] == '0x0105b79c', cls

    # ---- Plant-only structural gates
    assert by['Plant']['save_time_read_back'] is True
    reset = by['Plant']['save_time_reset']
    assert reset['key'] == 'saveTime' and reset['conversion'] == 'doubleValue'
    assert reset['threshold_double'] == 1800.0
    assert reset['world_ivar_offset'] == 4
    assert reset['world_time_selector'] == 'worldTime'
    assert reset['branch_site'] == '0x00955930'
    assert reset['reset_ivar'] == 'OBJC_IVAR_$_Plant.hasFloweredThisSeason'
    assert reset['reset_store_site'] == '0x00955950'
    clamp = by['Plant']['gene_clamp']
    assert clamp['helper'] == '0x004c0b70' and clamp['bounds'] == [1, 255]
    assert [a['ivar'] for a in clamp['applied']] == [
        'OBJC_IVAR_$_Plant.maxAgeGene', 'OBJC_IVAR_$_Plant.growthRateGene']
    gates = set(by['Plant']['site_gates'])
    for g in ('bound_lo_movw_1@0x009554b4', 'bound_hi_movw_ff@0x009554b8',
              'clamp_maxagegene_call@0x009557fc',
              'clamp_growthrategene_call@0x0095583c',
              'vsub_f64@0x00955918', 'vcmpe_f64@0x00955928',
              'ble_gate@0x00955930', 'reset_hfts_store@0x00955950'):
        assert g in gates, g

    # ---- save/load asymmetry table (computed, cross-batch)
    fam = d['family']
    per = fam['per_class_read_write']
    assert per['Plant']['write_only'] == ['growthRate', 'maxAge']
    assert per['Plant']['read_only'] == []
    assert per['Tree']['write_only'] == ['saveTime']
    assert per['GemTree']['write_only'] == []
    assert per['CactusTree']['write_only'] == []
    assert per['CoconutTree']['write_only'] == []
    assert per['CactusTree']['symmetric'] is True
    assert per['GemTree']['symmetric'] is True
    assert fam['class_hierarchy']['GemTree'] == 'Tree'
    assert fam['class_hierarchy']['Plant'] == 'DynamicObject'
    # shared CFString objects prove cross-side pairing (Plant additionally
    # reads saveTime with no ivar store, hence compare against the pools)
    assert set(by['Plant']['save_side']['shared_cfstring_objects']) == \
        set(by['Plant']['pool_keys'])
    assert set(by['GemTree']['save_side']['shared_cfstring_objects']) == \
        set(by['GemTree']['pool_keys'])

    # ---- listings: word counts + forbidden keys absent from the pools
    for cls, (name, words) in LISTINGS.items():
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t,
                           re.MULTILINE))
        assert n == words, (name, n)
        assert '# implementation:' in t, name
    plant_listing = (NATIVE / LISTINGS['Plant'][0]).read_text()
    for absent in ("'growthRate'", "'maxAge'"):
        assert absent not in plant_listing, absent
    coco = (NATIVE / LISTINGS['CoconutTree'][0]).read_text()
    assert 'CFString key' not in coco, 'CoconutTree must have no key cells'

    print('b3b evidence: PASS')


if __name__ == '__main__':
    main()
