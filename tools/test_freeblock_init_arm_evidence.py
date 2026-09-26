#!/usr/bin/env python3
"""CI-safe evidence guard for the FreeBlock loader ARM differential (b4p).

Host (pinned ELF + Unicorn present): runs the differential and asserts every
case matches bit-exactly against -O0 and -O2.
CI: asserts the recovered contract, CTest/CMake/workflow registrations, the
trace-code single source of truth and the frozen executed facts.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
IMP = '0x00626a68'


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'freeblock_init.h').read_text()
    source = (RECOVERED / 'freeblock_init.cpp').read_text()
    contract = (ROOT / 'tools/test_freeblock_init.cpp').read_text()
    harness = (ROOT / 'tools/test_freeblock_init_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    workflow_android = (ROOT / '.github/workflows/android.yml').read_text()
    listing = (NATIVE / 'disasm_freeblock_big_initwithworld.txt').read_text()

    assert IMP in header.lower() and 'b4p' in header
    assert 'initWithWorld:dynamicWorld:saveDict:cache:' in header
    assert 'kFreeblockImageSize = 156' in header
    assert 'generated/trace_codes.h' in header
    # executed facts
    assert 'kFreeblockHoversAgeLimit = 900.0f' in header
    assert 'kFreeblockSkippedItemType = 11' in header
    assert 'kFreeblockGroundFallMaxSteps = 16' in header
    assert 'kFreeblockGroundSolidKind = 2' in header
    assert 'kFreeblockBlacklist627C40' in header
    assert 'kFreeblockLiquid5B2AD4' in header
    assert 'receiver = self->dynamicWorld (executed fact)' in header
    assert 're-anchor targets CREATION TIME, not floatPos' in header
    assert 'is an ARRAY' in header or 'ARRAY OF ARRAYS' in header

    generated = (RECOVERED / 'generated/trace_codes.h').read_text()
    for snippet in ('FreeblockInitCall', 'MsgSendSuper', 'ObjectForKeyBounceTimer',
                    'FloatValueBounceTimer', 'ObjectForKeySubItems',
                    'CountByEnumerating', 'InventoryAlloc',
                    'InventoryInitWithSaveData', 'InventoryItemType',
                    'SubItemsAddObject', 'ObjectForKeyDynSaveDict',
                    'ObjectForKeyPriorityId', 'BlockheadWithID',
                    'InitSubDerivedObjects', 'WorldTime', 'UpdatePosition',
                    'WorldTileQuery', 'ObjectType', 'DynamicWorldChangedAtPos'):
        assert snippet in generated, snippet
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_trace_codes.py'), '--check'],
                         capture_output=True, text=True)
    assert gen.returncode == 0, gen.stdout + gen.stderr
    assert 'FREEBLOCK_INIT_CODES' in harness

    # Contract semantics markers (each one is a decoded fact, not a choice).
    assert '0x5E1A0B80u' in source          # fresh array stored in subItems
    assert 'itemToken' not in source[:60]
    assert 'kFreeblockSkippedItemType' in source
    assert 'creation' in source             # creationTime re-anchor
    assert 'elapsed' in source
    for marker in ('super_nil', 'plain_keys', 'subitems_walk', 'priority_resolve',
                   'priority_zero', 'hovers_fresh', 'hovers_liquid_helper',
                   'hovers_inline_cd', 'hovers_blacklist', 'hovers_elapsed_big',
                   'ground_fall_two', 'ground_fall_one', 'ground_fall_soft_tile',
                   'ground_fall_limit', 'ground_fall_over_limit'):
        assert marker in harness, marker
    assert 'super2 own class' in harness
    assert 'memset' in harness             # the enum state zeroing stub
    assert 'enumerationMutation' in harness or '0x0105FD1C' in harness
    assert 'recovered_freeblock_init' in cmake
    assert 'test_freeblock_init_arm_evidence.py' in workflow
    assert 'implemented | 54' in workflow_android
    assert 'semantics | 54' in workflow_android
    assert 'boundary: 0x00627f74' in listing
    for anchor in (IMP, '0x00e8bc78', '0x00627c40'):
        assert anchor in listing, anchor
    # the helper call sites inside the body
    for site in ('bl #0xa12f24', 'bl #0x4b49fc', 'bl #0x4bdaac',
                 'bl #0xa12300', 'bl #0x627c40', 'bl #0x5b2ad4'):
        assert site in listing, site

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/freeblock-arm-differential'
        r = subprocess.run([sys.executable,
                            str(ROOT / 'tools/test_freeblock_init_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('FreeBlock ARM differential failed')
        report = json.loads((out / 'freeblock_init_arm_result.json').read_text())
        assert report['match'] is True
        assert report['cases'] >= 15
        walk = next(r for r in report['rows'] if r['case'] == 'subitems_walk')
        assert walk['trace_len'] >= 60, walk
        fall = next(r for r in report['rows'] if r['case'] == 'ground_fall_two')
        assert fall['tile_queries'] == 3, fall
        print(f"b4p ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4p evidence: static contract only (no pinned ELF or no Unicorn)')

    print('b4p evidence: PASS')


if __name__ == '__main__':
    main()
