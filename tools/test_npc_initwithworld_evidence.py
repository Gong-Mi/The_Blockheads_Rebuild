#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-b3g NPC init evidence.

Host (pinned ELF present): recovery tool `--check` + `--self-test`.
CI (ELF absent): static content assertions + listing word count.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'npc_initwithworld.json'
RECOVER = ROOT / 'tools/recover_npc_initwithworld.py'
LISTING = NATIVE / 'disasm_npc_initwithworld.txt'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if ELF.exists():
        for args, label in ((['--check'], 'stale npc_initwithworld.json'),
                            (['--self-test'], 'b3g negative controls failed')):
            r = subprocess.run([sys.executable, str(RECOVER), str(ELF)] + args,
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(r.stdout + r.stderr)
                raise SystemExit(label)
            print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA and d['batch'] == 'b3g'
    assert d['class'] == 'NPC'
    assert (d['imp'], d['boundary'], d['code_words']) == \
        ('0x00644b24', '0x00644ca0', 95)
    assert d['selector'] == 'initWithWorld:dynamicWorld:saveDict:cache:'

    si = d['super_init']
    assert si['superref_slot'] == '0x00e8bc84'
    assert si['class_object'] == 'OBJC_CLASS_$_NPC'
    assert si['runtime_superclass'] == 'DynamicObject'
    assert si['got_slot'] == '0x0105b79c' and si['call_word_index'] == 38

    pl = d['post_load']
    assert pl['selector'] == 'loadValuesFromSaveDict:'
    assert pl['selector_cell'] == '0x00e7f104'
    assert 'saveDict' in pl['argument']

    seed = d['hunger_timer_seed']
    assert seed['ivar'] == 'OBJC_IVAR_$_NPC.randomHarmFromHungerTimer'
    assert seed['ivar_offset'] == 144
    assert 'lrand48' in seed['formula'] and '2^31' in seed['formula']
    assert seed['range'].startswith('[1.0, 21.0]')
    assert seed['determinism'].startswith('NON-deterministic')

    chain = d['lrand48_chain']
    assert chain['import'] == 'lrand48'
    assert chain['slot'] == '0x0105fb10'
    assert chain['veneer'] == '0x001c2804'
    assert chain['wrapper'] == '0x006445d8'
    assert chain['wrapper_words'] == ['e92d4800', 'e1a0b00d', 'ebedf887',
                                      'e8bd8800']

    assert d['shape'] == {'super_call_word_index': 38,
                          'nil_guard_word_indices': [44, 45],
                          'return_nil_word_indices': [46, 47, 48],
                          'loadValues_call_word_index': 61,
                          'lrand48_wrapper_call_word_index': 62,
                          'timer_store_word_index': 79}
    assert d['pool_keys'] == []
    assert d['selrefs'] == ['initWithWorld:dynamicWorld:saveDict:cache:',
                            'loadValuesFromSaveDict:']

    t = LISTING.read_text()
    n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
    assert n == 95, n
    assert '# -[NPC initWithWorld:dynamicWorld:saveDict:cache:]' in t

    print('b3g evidence: PASS')


if __name__ == '__main__':
    main()
