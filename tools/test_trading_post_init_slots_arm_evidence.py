#!/usr/bin/env python3
"""CI-safe evidence guard for TradingPost initSlotsWithSaveDict: ARM differential (batch b4j).

Host, when both the pinned ELF and Unicorn are present: runs the differential
and asserts all cases match bit-exactly against -O0 and -O2.
Without them (CI): asserts the recovered C++ contract, CTest registration,
CMake/workflow registrations, trace code drift check, and that the b3n decode
of TradingPost is still the frozen one.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
IMP = '0x005e4914'


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'trading_post_init_slots.h').read_text()
    source = (RECOVERED / 'trading_post_init_slots.cpp').read_text()
    contract = (ROOT / 'tools/test_trading_post_init_slots.cpp').read_text()
    harness = (ROOT / 'tools/test_trading_post_init_slots_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    listing = (NATIVE / 'disasm_tradingpost_initslotswithsavedict.txt').read_text()
    hooks = json.loads((NATIVE / 'hooks6_persistence_closeout.json').read_text())

    # Contract header documents IMP and batch
    assert '0x005E4914' in header and 'b4j' in header
    assert 'initSlotsWithSaveDict:' in header
    assert 'generated/trace_codes.h' in header

    # Trace codes single source of truth
    generated = (RECOVERED / 'generated/trace_codes.h').read_text()
    for snippet in ('AllocNSMutableArray', 'InitNSMutableArray', 'ObjectForKey',
                    'FastEnumeration', 'AllocInventoryItem', 'InitWithSaveData',
                    'AutoreleaseItem', 'ItemType', 'AddObject'):
        assert snippet in generated, snippet

    # Trace codes: single source of truth check
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_trace_codes.py'), '--check'],
                         capture_output=True, text=True)
    assert gen.returncode == 0, gen.stdout + gen.stderr
    assert 'trace_codes_gen' in harness

    # Contract source stores sellSlot at 100, needsToUpdateBitmapString at 124, filters itemType 11
    assert 'store_word(result.image, 100, in.sell_slot_array_token)' in source
    assert 'store_byte(result.image, 124, 1)' in source
    assert 'item_entry.item_type != 11' in source

    # Contract test asserts cases
    assert 'missing_sell_slot' in harness
    assert 'chunked_items_cross_16' in harness
    assert 'recovered_trading_post_init_slots' in cmake
    assert 'test_trading_post_init_slots_arm_evidence.py' in workflow

    # The b3n decode for TradingPost must still match
    tp_entry = next((c for c in hooks['classes'] if c['class'] == 'TradingPost'), None)
    assert tp_entry is not None, 'TradingPost missing from hooks6'
    assert tp_entry['imp'] == IMP
    assert tp_entry['code_words'] == 243

    assert '0x005e4914' in listing
    assert '0x005e4ca0' in listing

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/trading-post-arm-differential'
        r = subprocess.run([sys.executable, str(ROOT / 'tools/test_trading_post_init_slots_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('TradingPost ARM differential failed')
        report = json.loads((out / 'trading_post_init_slots_arm_result.json').read_text())
        assert report['match'] is True
        assert report['cases'] >= 5
        print(f"b4j ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4j evidence: static contract only (no pinned ELF or no Unicorn '
              'on this host)')

    print('b4j evidence: PASS')


if __name__ == '__main__':
    main()
