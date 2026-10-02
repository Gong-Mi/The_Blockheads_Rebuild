#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-b3c craftable-item init evidence.

Host (pinned ELF present): re-runs the recovery script with `--check`
(byte-identical JSON) and `--self-test` (all mutations must be caught).
CI (ELF absent): static content assertions + listing word counts.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'craftableitem_initsavedict.json'
RECOVER = ROOT / 'tools/recover_craftableitem_initsavedict.py'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
LISTINGS = {
    'CraftableItemObject': ('disasm_craftableitemobject_initsavedict.txt', 85),
    'PaintingCraftableItemObject': (
        'disasm_paintingcraftableitemobject_initsavedict.txt', 103),
    'BlockheadCraftableItemObject': (
        'disasm_blockheadcraftableitemobject_initsavedict.txt', 788),
}


def main():
    if ELF.exists():
        for args, label in ((['--check'], 'stale craftableitem_initsavedict.json'),
                            (['--self-test'], 'b3c negative controls failed')):
            r = subprocess.run([sys.executable, str(RECOVER), str(ELF)] + args,
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(r.stdout + r.stderr)
                raise SystemExit(label)
            print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA and d['batch'] == 'b3c'
    assert 'initWithSaveDict' in d['method']
    by = {c['class']: c for c in d['classes']}
    assert set(by) == set(LISTINGS)

    expect = {
        'CraftableItemObject': ('0x00ac7900', '0x00ac7a54', 85,
                                'super_init_then_blob'),
        'PaintingCraftableItemObject': ('0x00741e18', '0x00741fb4', 103,
                                        'super_init_then_retain'),
        'BlockheadCraftableItemObject': ('0x00810f10', '0x00811b60', 788,
                                          'dual_source_skinoptions'),
    }
    for cls, (imp, boundary, words, style) in expect.items():
        c = by[cls]
        assert (c['imp'], c['boundary'], c['code_words'], c['style']) == \
            (imp, boundary, words, style), cls
        assert c['selector'] == 'initWithSaveDict:'
        ng = c['nil_guard']
        assert (ng['cmp_site'], ng['bne_site']) == \
            {'CraftableItemObject': ('0x00ac7970', '0x00ac7974'),
             'PaintingCraftableItemObject': ('0x00741e8c', '0x00741e90'),
             'BlockheadCraftableItemObject': ('0x00810f84', '0x00810f88')}[cls]
        si = c['super_init']
        assert si['got_slot'] == '0x0105b79c'
        assert si['superref_slot'] == {'CraftableItemObject': '0x00e8be74',
            'PaintingCraftableItemObject': '0x00e8bd0c',
            'BlockheadCraftableItemObject': '0x00e8bd6c'}[cls]
        assert si['call_site'] == {'CraftableItemObject': '0x00ac7958',
            'PaintingCraftableItemObject': '0x00741e74',
            'BlockheadCraftableItemObject': '0x00810f6c'}[cls]

    # super-init selectors and class-struct facts
    assert by['CraftableItemObject']['super_init']['selector'] == 'init'
    assert by['CraftableItemObject']['super_init']['root_class'] is True
    assert by['CraftableItemObject']['super_init']['runtime_superclass'] is None
    assert by['CraftableItemObject']['super_init']['instance_size'] == 128
    assert by['CraftableItemObject']['super_init']['record_fit'] == [4, 124]
    for cls, sel in (('PaintingCraftableItemObject', 'initWithSaveDict:'),
                     ('BlockheadCraftableItemObject', 'initWithSaveDict:')):
        si = by[cls]['super_init']
        assert si['selector'] == sel, cls
        assert si['runtime_superclass'] == 'CraftableItemObject', cls
        assert si['root_class'] is False, cls
        assert (si['instance_start'], si['instance_size']) == (128, 136 if cls.startswith('Painting') else 152)

    # key chains
    cio = by['CraftableItemObject']['keys']
    assert len(cio) == 1 and cio[0]['key'] == 'craftableItem'
    assert cio[0]['form'] == 'blob_getbytes' and cio[0]['length'] == 124
    assert cio[0]['ivar_offset'] == 4 and cio[0]['store_kind'] == 'blob_store'
    assert cio[0]['cfstring_object'] == '0x00f9b7b8'
    assert by['CraftableItemObject']['blob']['length_word'] == 'e300307c'

    ptg = {k['key']: k for k in by['PaintingCraftableItemObject']['keys']}
    assert set(ptg) == {'imageData', 'outputImageData'}
    for key, off, cf in (('imageData', 128, '0x00f8ceb8'),
                         ('outputImageData', 132, '0x00f8cec8')):
        assert ptg[key]['form'] == 'retain_object', key
        assert ptg[key]['conversion'] == 'retain', key
        assert ptg[key]['ivar_offset'] == off and ptg[key]['cfstring_object'] == cf
    assert by['PaintingCraftableItemObject']['save_side']['write_only'] == \
        ['craftableObjectType']

    bhc = by['BlockheadCraftableItemObject']
    assert [k['key'] for k in bhc['keys']] == ['name']
    assert bhc['keys'][0]['ivar_offset'] == 128
    so = bhc['skin_options']
    assert so['record_bytes'] == 20 and so['dual_source'] is True
    assert so['ivar_offset'] == 132
    assert so['blob_path']['blob_absent_branch'] == '0x0081104c'
    assert so['blob_path']['length_movw_site'] == '0x00811050'
    assert so['scalar_path']['helper_call_site'] == '0x0081125c'
    assert so['scalar_path']['memcpy_site'] == '0x00811278'
    assert [s['key'] for s in so['scalar_path']['scalars']] == \
        ['isMale', 'headIndex', 'skinIndex', 'hairStyleIndex']
    assert [s['conversion'] for s in so['scalar_path']['scalars']] == \
        ['boolValue', 'intValue', 'intValue', 'intValue']
    assert so['scalar_path']['scalars'][0]['sxtb_site'] == '0x00811244'
    assert so['pack_helper']['imp'] == '0x008112d8'
    assert so['pack_helper']['decoded_in_batch'] is False
    assert so['pack_helper']['memcpy'] == '0x001c2894'
    assert bhc['save_side']['write_only'] == ['craftableObjectType']
    assert bhc['save_side']['read_only'] == \
        ['hairStyleIndex', 'headIndex', 'isMale', 'skinIndex']

    for cls, (name, words) in LISTINGS.items():
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t,
                           re.MULTILINE))
        assert n == words, (name, n)
        assert '# implementation:' in t, name

    print('b3c evidence: PASS')


if __name__ == '__main__':
    main()
