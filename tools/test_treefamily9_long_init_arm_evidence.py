#!/usr/bin/env python3
"""CI-safe evidence guard for the nine tree-family LONG loaders (batch b4r).

The static decode is b3i (nine byte-identical 62-word bodies, one shared
skeleton, per-class superref/selector tail cells). This guard pins that decode
and the artifacts this batch added, and — when the pinned ELF and Unicorn are
both present (host) — re-runs the Unicorn differential and asserts its report.

CI has no pinned ELF, so there it degrades to static content assertions plus
`gen_treefamily9_class_table.py --check` (the generated per-class table must
still match the frozen b3i JSON word for word).

    python3 tools/test_treefamily9_long_init_arm_evidence.py          # host/CI
    HOME=<empty dir> python3 tools/test_treefamily9_long_init_arm_evidence.py
                                                                     # CI mode
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
ELF_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BODY_SHA = '0e8602818e17da1dec064c73afc901040ccef3c477b0ef8f7654c5beec4db765'
SELECTOR = ('initWithWorld:dynamicWorld:saveDict:cache:'
            'treeDensityNoiseFunction:seasonOffsetNoiseFunction:')
ENTRIES = {'CactusTree', 'CherryTree', 'CoconutTree', 'CoffeeTree', 'GemTree',
           'LimeTree', 'MangoTree', 'MapleTree', 'OrangeTree'}
GUARD = 'test_treefamily9_long_init_arm_evidence.py'


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'treefamily9_long_init.h').read_text()
    source = (RECOVERED / 'treefamily9_long_init.cpp').read_text()
    wrappers = (RECOVERED / 'treefamily9_long_init_classes.h').read_text()
    table = (RECOVERED / 'treefamily9_long_init_classes.inc').read_text()
    contract = (ROOT / 'tools/test_treefamily9_long_init.cpp').read_text()
    harness = (ROOT / 'tools/test_treefamily9_long_init_arm.py').read_text()
    module = (ROOT / 'tools/arm_harness/super_forward.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    decode = json.loads(
        (NATIVE / 'treefamily9_long_initwithworld.json').read_text())

    # --- the recovered contract is shared, the wrappers are thin ------------
    assert 'treefamily9_long_init_forward' in header
    assert 'b3i' in header and 'executed at Level-B' in header
    assert 'BLOCKHEADS_TREE9_ROW' in wrappers and 'BLOCKHEADS_TREE9_ROW' in table
    assert 'objc_msgSendSuper2' in header
    assert 'super_returns_nil' in source and 'no CFString key' in header
    assert 'kArgSeasonOffsetNoiseFunction' in header
    # the shared module owns the Unicorn shape; the shell stays thin
    assert 'class SuperForwardDifferential' in module
    assert 'SuperForwardDifferential' in harness
    assert 'run_one' in harness and 'MUTATIONS' in harness

    # --- frozen b3i decode --------------------------------------------------
    assert decode['elf_sha256'] == ELF_SHA
    assert decode['selector'] == SELECTOR
    classes = {c['class']: c for c in decode['classes']}
    assert set(classes) == ENTRIES, sorted(classes)
    for name, c in classes.items():
        assert c['code_words'] == 62, name
        assert c['shared_body_sha256'] == BODY_SHA, name
        assert c['runtime_superclass'] == 'Tree', name
        assert c['own_keys'] == [] and c['own_ivars'] == [], name
        assert c['selector'] == SELECTOR, name
        assert f'{name}, "{name}"' in table, name
    # the nine share ONE body: the decode must not claim a second skeleton
    assert len({c['shared_body_sha256'] for c in classes.values()}) == 1

    # --- registrations ------------------------------------------------------
    assert 'blockheads_recovered_treefamily9_long' in cmake
    assert 'recovered_treefamily9_${tree_class}_long_init' in cmake
    assert GUARD in workflow, 'evidence guard not registered in the workflow'
    assert 'treefamily9_long_init.cpp' in cmake
    assert 'treefamily9_long_init_forward' in contract

    # the generated per-class table must still match the frozen decode
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_treefamily9_class_table.py'),
                          '--check'], capture_output=True, text=True)
    if gen.returncode != 0:
        print(gen.stdout + gen.stderr)
        raise SystemExit('b4r: generated class table drifted from the b3i JSON')

    if ELF.exists() and have_unicorn():
        if __import__('hashlib').sha256(ELF.read_bytes()).hexdigest() != ELF_SHA:
            raise SystemExit('pinned ELF SHA mismatch')
        out = ROOT / 'scratch/treefamily9-long-arm-differential'
        r = subprocess.run([sys.executable,
                            str(ROOT / 'tools/test_treefamily9_long_init_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('b4r: tree-family LONG ARM differential failed')
        report = json.loads(
            (out / 'treefamily9-long-init-arm-result.json').read_text())
        assert report['match'] is True
        assert report['identical_trace_across_entries'] is True
        assert report['entries'] == 9 and report['cases'] == 18
        assert report['arg_order'] == ['world', 'dynamicWorld', 'saveDict',
                                       'cache', 'treeDensity', 'seasonOffset']
        print(f"b4r ARM differential: {report['entries']} entries / "
              f"{report['cases']} cases matched, identical traces")
    else:
        print('b4r evidence: static contract only (no pinned ELF or no Unicorn '
              'on this host)')

    print('b4r evidence: PASS')


if __name__ == '__main__':
    main()
