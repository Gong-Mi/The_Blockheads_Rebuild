#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-b3f five-forwarder evidence.

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
OUT = NATIVE / 'forwarder5_initwithworld.json'
RECOVER = ROOT / 'tools/recover_forwarder5_initwithworld.py'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
SKELETON_SHA = ('bbd0bc16ac1ca4e3776bafe9153a6067'
                '2ca15a66b68d4efffad33581d804f1c8')
CLASSES = {
    'ClownFish': ('0x0078e420', '0x0078e548'),
    'Shark': ('0x007c8918', '0x007c8a40'),
    'Scorpion': ('0x00893d58', '0x00893e80'),
    'Dodo': ('0x00a6b7dc', '0x00a6b904'),
    'DonkeyLike': ('0x00ab0c3c', '0x00ab0d64'),
}
LISTINGS = {c: f'disasm_{c.lower()}_initwithworld.txt' for c in CLASSES}


def main():
    if ELF.exists():
        for args, label in ((['--check'], 'stale forwarder5_initwithworld.json'),
                            (['--self-test'], 'b3f negative controls failed')):
            r = subprocess.run([sys.executable, str(RECOVER), str(ELF)] + args,
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(r.stdout + r.stderr)
                raise SystemExit(label)
            print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA and d['batch'] == 'b3f'
    assert d['selector'] == 'initWithWorld:dynamicWorld:saveDict:cache:'
    assert d['shared_skeleton_sha256'] == SKELETON_SHA
    assert d['shared_skeleton_words'] == 69
    assert d['census'] == {'selector_methods': 43, 'selector_words': 10976,
                           'covered_by_this_batch': 5}
    by = {c['class']: c for c in d['classes']}
    assert set(by) == set(CLASSES)
    for cls, (imp, boundary) in CLASSES.items():
        c = by[cls]
        assert (c['imp'], c['boundary'], c['code_words']) == (imp, boundary, 74), cls
        assert c['selector'] == d['selector']
        assert c['skeleton_sha256'] == SKELETON_SHA, cls
        assert c['skeleton_words'] == 69, cls
        assert c['runtime_superclass'] == 'NPC', cls
        assert c['own_keys'] == [] and c['own_ivars'] == [], cls
        lc = c['literal_cells']
        assert lc['super2_got'] == '0x0105b79c', cls
        assert lc['msgsend_got'] == '0x0105b7a0', cls
        assert lc['class_object'] == f'OBJC_CLASS_$_{cls}', cls
        assert lc['super_selector_cell'].startswith('0x00e8'), cls
        assert lc['loadDerivedStuff_selector_cell'].startswith('0x00e8'), cls
        assert re.fullmatch(r'0x00e8[0-9a-f]{4}', lc['superref_slot']), cls
        assert lc['pic_base_cell_word'] == 'unmapped', cls
        assert c['shape'] == {'super_call_word_index': 41,
                              'nil_guard_word_indices': [43, 47, 48],
                              'return_nil_indices': [49, 51],
                              'loadDerivedStuff_call_word_index': 62}, cls
    assert len({c['skeleton_sha256'] for c in d['classes']}) == 1

    for cls, name in LISTINGS.items():
        t = (NATIVE / name).read_text()
        n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t,
                           re.MULTILINE))
        assert n == 74, (name, n)
        assert f'# -[{cls} initWithWorld:dynamicWorld:saveDict:cache:]' in t, name

    print('b3f evidence: PASS')


if __name__ == '__main__':
    main()
