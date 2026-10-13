#!/usr/bin/env python3
"""CI-safe evidence guard for DynamicObject initDerivedStuff:loadPhysicalBlockIfNeeded: ARM differential (batch b4k).

Host, when both the pinned ELF and Unicorn are present: runs the differential
and asserts all cases match bit-exactly against -O0 and -O2.
Without them (CI): asserts the recovered C++ contract, CTest registration,
CMake/workflow registrations, trace code drift check, and that the b3n decode
of DynamicObject is still the frozen one.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
IMP = '0x00839508'


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'dynamic_object_init_derived_stuff.h').read_text()
    source = (RECOVERED / 'dynamic_object_init_derived_stuff.cpp').read_text()
    contract = (ROOT / 'tools/test_dynamic_object_init_derived_stuff.cpp').read_text()
    harness = (ROOT / 'tools/test_dynamic_object_init_derived_stuff_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    listing = (NATIVE / 'disasm_dynamicobject_initderivedstuff.txt').read_text()
    hooks = json.loads((NATIVE / 'hooks6_persistence_closeout.json').read_text())

    # Contract header documents IMP and batch
    assert '0x00839508' in header and 'b4k' in header
    assert 'initDerivedStuff:loadPhysicalBlockIfNeeded:' in header
    assert 'generated/trace_codes.h' in header

    # Trace codes single source of truth
    generated = (RECOVERED / 'generated/trace_codes.h').read_text()
    for snippet in ('WorldMacroTiles', 'LoadPhysicalBlock', 'ShouldAddToMacroBlock',
                    'LoadDynamicObjects', 'AddObject', 'ObjectType', 'DynamicWorldChanged'):
        assert snippet in generated, snippet

    # Trace codes: single source of truth check
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_trace_codes.py'), '--check'],
                         capture_output=True, text=True)
    assert gen.returncode == 0, gen.stdout + gen.stderr
    assert 'trace_codes_gen' in harness

    # Contract source stores macroTileOwner at 12
    assert 'store_word(result.image, 12, in.macro_tile_ptr)' in source
    assert 'LoadPhysicalBlock' in source
    assert 'ShouldAddToMacroBlock' in source

    # Contract test asserts cases
    assert 'happy_path_with_init' in harness
    assert 'nil_macro_tile' in harness
    assert 'recovered_dynamic_object_init_derived' in cmake
    assert 'test_dynamic_object_init_derived_stuff_arm_evidence.py' in workflow

    # The b3n decode for DynamicObject must still match
    obj_entry = next((c for c in hooks['classes'] if c['class'] == 'DynamicObject' and c['selector'] == 'initDerivedStuff:loadPhysicalBlockIfNeeded:'), None)
    assert obj_entry is not None, 'DynamicObject initDerivedStuff missing from hooks6'
    assert obj_entry['imp'] == IMP
    assert obj_entry['code_words'] == 242

    assert '0x00839508' in listing
    assert '0x00839890' in listing

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/dynamic-object-derived-arm-differential'
        r = subprocess.run([sys.executable, str(ROOT / 'tools/test_dynamic_object_init_derived_stuff_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('DynamicObject ARM differential failed')
        report = json.loads((out / 'dynamic_object_init_derived_stuff_arm_result.json').read_text())
        assert report['match'] is True
        assert report['cases'] >= 5
        print(f"b4k ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4k evidence: static contract only (no pinned ELF or no Unicorn '
              'on this host)')

    print('b4k evidence: PASS')


if __name__ == '__main__':
    main()
