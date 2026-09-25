#!/usr/bin/env python3
"""CI-safe evidence guard for the Tree growInTimeSinceSaved: ARM
differential (batch b4g, stage 1 nil-tile path).

Host, when both the pinned ELF and Unicorn are present: runs the full ARM
differential and asserts it matched. Without them (CI): asserts the
structural artifacts — the recovered C++ module, its CTest contract, the
differential's case list, the CMake/CTest registration, the workflow
registration of this guard, and the b3n decode record this stage claims
to implement.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
CASES = ['static', 'dead_entry', 'partial', 'double_increment',
         'scripted_height_exit', 'compost', 'death', 'nan_worldtime',
         'negative_elapsed', 'boundary', 'tile_sunlight',
         'tile_artificial_light']


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'tree_grow_in_time.h').read_text()
    source = (RECOVERED / 'tree_grow_in_time.cpp').read_text()
    contract = (ROOT / 'tools/test_tree_grow_in_time.cpp').read_text()
    harness = (ROOT / 'tools/test_tree_grow_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    listing = (NATIVE / 'disasm_tree_growintimesincesaved.txt').read_text()
    hooks = json.loads((NATIVE / 'hooks6_persistence_closeout.json').read_text())

    # The module documents what it implements and where the decode lives.
    assert '0x004c2568' in header and 'b4g' in header
    assert 'growInTimeSinceSaved:' in header
    assert 'generated/trace_codes.h' in header
    generated = (RECOVERED / 'generated/trace_codes.h').read_text()
    for snippet in ('IsStaticTree', 'WorldTime', 'IncrementHeight',
                    'UpdateGrowthAdult', 'SowTreeNearParent',
                    'RemoveAllOwnedTiles'):
        assert snippet in generated, snippet
    # The behavioral claims: 0.005 constant, the spilled timeToGrow = 1.0f
    # after an increment, the corrected partial formula gc + (1-gc)*eg,
    # the -1.0 elapsed exit, the timeDied order.
    assert '0.005' in source
    assert '(1.0f - growth_counter) * e_over_g' in source
    assert 'time_to_grow = 1.0f' in source
    assert 'elapsed = -1.0' in source
    assert 'in.time_since_saved + (double)max_age - (double)age' in source

    # The contract test pins the same facts the harness executes.
    for snippet in ('115.0', '85.0f', 'maxHeightReached', 'nan',
                    'two increments', 'compost'):
        assert snippet in contract, snippet

    # Harness and guard agree on the case list; the tile-lookup constant
    # lives in tools/arm_harness/world.py (consolidated fixture library).
    for name in CASES:
        assert f"'{name}'" in harness, name
    world_mod = (ROOT / 'tools/arm_harness/world.py').read_text()
    assert 'ACCESSOR_IMP = 0x00A12F24' in world_mod
    assert 'WorldAnswers' in harness and 'arm_harness' in harness
    assert '0x004c2569' not in listing  # listing starts exactly at the IMP
    assert '0x004c2df0' in listing

    # Trace codes: single source of truth, no drift possible.
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_trace_codes.py'), '--check'],
                         capture_output=True, text=True)
    assert gen.returncode == 0, gen.stdout + gen.stderr
    assert 'trace_codes_gen' in harness

    # Registration in both places.
    assert 'tree_grow_in_time.cpp' in cmake
    assert 'recovered_tree_grow_in_time' in cmake
    assert 'test_tree_grow_arm_evidence.py' in workflow

    # The b3n decode this stage implements must still be the frozen one.
    assert 'growInTimeSinceSaved' in hooks['claim']
    assert hooks['census']['persistence_core_methods'] == 149

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/tree-grow-arm-differential'
        r = subprocess.run([sys.executable,
                            str(ROOT / 'tools/test_tree_grow_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('ARM differential failed')
        report = json.loads((out / 'tree-grow-arm-result.json').read_text())
        assert report['match'] is True
        assert report['cases'] == len(CASES), report['cases']
        assert report['stage'] == 1
        assert report['boundary'].startswith('Unicorn execution')
        print(f"b4g ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4g evidence: static contract only (no pinned ELF or no '
              'Unicorn on this host)')

    print('b4g evidence: PASS')


if __name__ == '__main__':
    main()
