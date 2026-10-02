#!/usr/bin/env python3
"""CI-safe evidence guard for TradePortal loadPriceOffsets: ARM differential (batch b4i).

Host, when both the pinned ELF and Unicorn are present: runs the differential
and asserts all cases match bit-exactly against -O0 and -O2.
Without them (CI): asserts the recovered C++ contract, CTest registration,
CMake/workflow registrations, trace code drift check, and that the b3n decode
of TradePortal is still the frozen one.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
IMP = '0x00d37a78'


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'trade_portal_price_offsets.h').read_text()
    source = (RECOVERED / 'trade_portal_price_offsets.cpp').read_text()
    contract = (ROOT / 'tools/test_trade_portal_price_offsets.cpp').read_text()
    harness = (ROOT / 'tools/test_trade_portal_price_offsets_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    listing = (NATIVE / 'disasm_tradeportal_loadpriceoffsets.txt').read_text()
    hooks = json.loads((NATIVE / 'hooks6_persistence_closeout.json').read_text())

    # Contract header documents IMP and batch
    assert '0x00D37A78' in header and 'b4i' in header
    assert 'loadPriceOffsets:' in header
    assert 'generated/trace_codes.h' in header

    # Trace codes single source of truth
    generated = (RECOVERED / 'generated/trace_codes.h').read_text()
    for snippet in ('FastEnumeration', 'ObjectForKey', 'DoubleValue',
                    'NumberWithDouble', 'SetObjectForKey'):
        assert snippet in generated, snippet

    # Trace codes: single source of truth check
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_trace_codes.py'), '--check'],
                         capture_output=True, text=True)
    assert gen.returncode == 0, gen.stdout + gen.stderr
    assert 'trace_codes_gen' in harness

    # Contract source stores localPriceOffsets at 128 and clamps [0.5, 2.0]
    assert 'store_word(result.image, 128, in.local_price_offsets_token)' in source
    assert 'clamp_price_offset' in source
    assert '0.5' in source and '2.0' in source

    # Contract test asserts cases
    assert 'clamp_low_edge' in harness
    assert 'clamp_high_edge' in harness
    assert 'recovered_trade_portal_price_offsets' in cmake
    assert 'test_trade_portal_price_offsets_arm_evidence.py' in workflow

    # The b3n decode for TradePortal must still match
    tp_entry = next((c for c in hooks['classes'] if c['class'] == 'TradePortal'), None)
    assert tp_entry is not None, 'TradePortal missing from hooks6'
    assert tp_entry['imp'] == IMP
    assert tp_entry['code_words'] == 197

    assert '0x00d37a78' in listing
    assert '0x00d37d8c' in listing

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/trade-portal-arm-differential'
        r = subprocess.run([sys.executable, str(ROOT / 'tools/test_trade_portal_price_offsets_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('TradePortal ARM differential failed')
        report = json.loads((out / 'trade_portal_price_offsets_arm_result.json').read_text())
        assert report['match'] is True
        assert report['cases'] >= 5
        print(f"b4i ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4i evidence: static contract only (no pinned ELF or no Unicorn '
              'on this host)')

    print('b4i evidence: PASS')


if __name__ == '__main__':
    main()
