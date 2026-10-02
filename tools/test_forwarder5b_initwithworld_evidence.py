#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-b3h five-forwarder evidence.

Host (pinned ELF present): recovery tool `--check` + `--self-test`.
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
OUT = NATIVE / 'forwarder5b_initwithworld.json'
RECOVER = ROOT / 'tools/recover_forwarder5b_initwithworld.py'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
CLASSES = {
    'SurfaceBlock': ('0x00812e64', '0x00812f48', 57, 'super_only',
                     'DynamicObject'),
    'PassengerCar': ('0x0081bcc8', '0x0081bdb8', 60, 'super_only', 'TrainCar'),
    'HandCar': ('0x00a4f564', '0x00a4f654', 60, 'super_only', 'TrainCar'),
    'Mirror': ('0x00a9f434', '0x00a9f550', 71,
               'super_plus_initSubDerivedItems', 'InteractionObject'),
    'SnowSurfaceBlock': ('0x00d8d89c', '0x00d8d9b8', 71,
                         'super_plus_initSubDerivedItems', 'DynamicObject'),
}
LISTINGS = {c: f'disasm_{c.lower()}_initwithworld.txt' for c in CLASSES}


def main():
    if ELF.exists():
        for args, label in ((['--check'], 'stale forwarder5b_initwithworld.json'),
                            (['--self-test'], 'b3h negative controls failed')):
            r = subprocess.run([sys.executable, str(RECOVER), str(ELF)] + args,
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(r.stdout + r.stderr)
                raise SystemExit(label)
            print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA and d['batch'] == 'b3h'
    assert d['selector'] == 'initWithWorld:dynamicWorld:saveDict:cache:'
    assert d['census'] == {'selector_methods': 43, 'selector_words': 10976,
                           'covered_after_b3h': 11,
                           'words_covered_after_b3h': 784,
                           'remaining_methods': 32, 'remaining_words': 10192}
    assert d['shapes'] == {
        'super_only': ['SurfaceBlock', 'PassengerCar', 'HandCar'],
        'super_plus_initSubDerivedItems': ['Mirror', 'SnowSurfaceBlock']}
    by = {c['class']: c for c in d['classes']}
    assert set(by) == set(CLASSES)
    for cls, (imp, boundary, words, shape, sup) in CLASSES.items():
        c = by[cls]
        assert (c['imp'], c['boundary'], c['code_words'], c['shape']) == \
            (imp, boundary, words, shape), cls
        assert c['runtime_superclass'] == sup, cls
        assert c['own_keys'] == [] and c['own_ivars'] == [], cls
        lc = c['literal_cells']
        assert lc['super2_got'] == '0x0105b79c', cls
        assert lc['class_object'] == f'OBJC_CLASS_$_{cls}', cls
        assert re.fullmatch(r'0x00e8[0-9a-f]{4}', lc['superref_slot']), cls
        assert lc['super_selector_cell'].startswith('0x00e8'), cls
        if shape == 'super_only':
            assert c['hook'] is None, cls
            assert lc['msgsend_got'] is None, cls
        else:
            assert c['hook']['selector'] == 'initSubDerivedItems', cls
            assert c['hook']['selector_cell'].startswith('0x00e8'), cls
            assert lc['msgsend_got'] == '0x0105b7a0', cls
        assert c['super_call_word_index'] in (37, 38, 40), cls

    for cls, name in LISTINGS.items():
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t,
                           re.MULTILINE))
        assert n == CLASSES[cls][2], (name, n)
        assert f'# -[{cls} initWithWorld:dynamicWorld:saveDict:cache:]' in t, name

    print('b3h evidence: PASS')


if __name__ == '__main__':
    main()
