#!/usr/bin/env python3
"""CI-safe evidence guard for the VinePlant BIG loader ARM differential (b4o).

Host (pinned ELF + Unicorn present): runs the differential and asserts every
case matches bit-exactly against -O0 and -O2.
CI: asserts the recovered contract, CTest/CMake/workflow registrations, the
trace-code single source of truth and the frozen b3m-1 static decode.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
IMP = '0x004f68a0'


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'vine_plant_init.h').read_text()
    source = (RECOVERED / 'vine_plant_init.cpp').read_text()
    contract = (ROOT / 'tools/test_vine_plant_init.cpp').read_text()
    harness = (ROOT / 'tools/test_vine_plant_init_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    listing = (NATIVE / 'disasm_vineplant_big_initwithworld.txt').read_text()
    b3m1 = json.loads((NATIVE / 'kelpvine_big_initwithworld.json').read_text())

    assert IMP in header.lower() and 'b4o' in header
    assert 'treeDensityNoiseFunction:seasonOffsetNoiseFunction:' in header
    assert 'kVineImageSize = 184' in header
    assert 'generated/trace_codes.h' in header
    assert 'kVineRandomDenominator = 2147483648.0f' in header   # 2^31 pool constant
    assert 'kVineRefillScale = 900.0f' in header

    generated = (RECOVERED / 'generated/trace_codes.h').read_text()
    for snippet in ('VineInitCall', 'MsgSendSuper', 'ObjectForKeyOccupied',
                    'IntValueOccupied', 'ObjectForKeyGrowthTimer',
                    'FloatValueGrowthTimer', 'InitSubDerivedItems',
                    'ObjectForKeyAvailableFood', 'FloatValueAvailableFood',
                    'Lrand48', 'ObjectForKeySaveTime', 'DoubleValueSaveTime',
                    'WorldTime', 'IsGrowingInCompost', 'DieOfOldAge',
                    'ObjectType', 'WorldContentsChangedAtPos',
                    'DynamicWorldChangedAtPos', 'WorldTileQuery'):
        assert snippet in generated, snippet
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_trace_codes.py'), '--check'],
                         capture_output=True, text=True)
    assert gen.returncode == 0, gen.stdout + gen.stderr
    assert 'VINE_INIT_CODES' in harness

    # Contract semantics markers (each one is a decoded fact, not a choice).
    assert 'as_float / kVineRandomDenominator * kVineRefillScale' in source
    assert 'kVineGrowthEnergy / factor' in source
    assert 'ARM `blt` edge' in source and 'ARM `bpl` edge' in source
    assert 'is_growing_in_compost' in source and 'kVineCompostAdjust' in source
    assert 'kVineLightGate' in source          # the EXTRA light/sun key
    assert 'kVineTileMarker = 0x7C' in header
    assert 'kVineRejectedTileKind = 3' in header   # inverted gate: kind must be 0
    assert 'kVineRejectedTileByte0 = 31' in header
    assert 'kVineMaxOccupiedTiles = 15' in header
    assert 'store_float' in source and 'low32' in source

    for marker in ('die_of_old_age', 'compost_adjust', 'growth_single_tile',
                   'growth_multi_tile', 'occupied_limit', 'food_refill',
                   'no_tile_answer', 'growth_blocked_kind3',
                   'growth_blocked_byte0_31', 'growth_light_boundary'):
        assert marker in harness, marker
    assert 'super2 own class' in harness
    assert "'worldTime receiver'" in harness
    assert 'initSubDerivedItems' in harness
    assert 'world accessor receiver' in harness
    assert 'recovered_vine_plant_init' in cmake
    assert 'test_vine_plant_init_arm_evidence.py' in workflow
    assert 'tools/gen_trace_codes.py --check' in workflow

    entry = next((c for c in b3m1['classes'] if c['class'] == 'VinePlant'), None)
    assert entry is not None, 'VinePlant missing from kelpvine_big_initwithworld.json'
    assert entry['imp'] == IMP
    assert entry['code_words'] == 681
    assert entry['runtime_superclass'] == 'Plant'
    assert sorted(entry['own_keys']) == ['availableFood', 'growthTimer',
                                         'numberOfOccupiedTilesBelow', 'saveTime']
    assert entry['literal_cells']['superref_slot'] == '0x00e8bc40'
    for anchor in (IMP, '0x4f688c', '0x4b49fc', '0xa12f24', '0x00e8bc40',
                   '0xa11690'):
        assert anchor in listing, anchor
    assert 'boundary: 0x004f7344' in listing   # next-IMP boundary (header)

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/vine-plant-arm-differential'
        r = subprocess.run([sys.executable,
                            str(ROOT / 'tools/test_vine_plant_init_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('VinePlant ARM differential failed')
        report = json.loads((out / 'vine_plant_init_arm_result.json').read_text())
        assert report['match'] is True
        assert report['cases'] >= 15
        multi = next(r for r in report['rows'] if r['case'] == 'growth_multi_tile')
        assert multi['tile_queries'] == 5, multi
        print(f"b4o ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4o evidence: static contract only (no pinned ELF or no Unicorn)')

    print('b4o evidence: PASS')


if __name__ == '__main__':
    main()
