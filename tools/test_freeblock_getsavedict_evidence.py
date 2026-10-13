#!/usr/bin/env python3
"""Regression contract for the bounded FreeBlock save-method inventory."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'


def main():
    report = json.loads((NATIVE / 'freeblock_getsavedict.json').read_text())
    assert report['method'] == 'FreeBlock -[getSaveDict]'
    assert report['imp'] == '0x00629804'
    assert report['code_end'] == '0x0062a410'
    assert report['boundary_end'] == '0x0062a4bc'
    assert report['code_words'] == 771
    assert report['coverage_words'] == 814
    assert report['pic_base'] == '0x0105faf4'
    assert report['selector_count'] == 12
    assert report['blx_count'] == 33
    assert report['direct_objc_msgsend_count'] == 1
    assert report['direct_objc_msgsend_sites'] == ['0x0062a3ac']
    assert report['known_imports'] == {
        'objc_msgSendSuper2': '0x0062a414',
        'objc_msgSend': '0x0062a428',
    }
    assert report['super_save_route'] == {
        'selector': 'getSaveDict',
        'dispatch': 'objc_msgSendSuper2',
        'selector_cell': '0x0062a418',
        'dispatch_cell': '0x0062a414',
    }
    for item in (
        'inherits DynamicObject dictionary via super getSaveDict',
        'boxes boolean/double/float/int values',
        'iterates an array with countByEnumeratingWithState:objects:count:',
        'reads itemType and saveData from contained objects',
        'adds serialized objects to an array',
        'writes additional fields through setObject:forKey:',
        'reads uniqueID',
    ):
        assert item in report['semantic_inventory']
    print('freeblock-getsavedict-evidence: PASS')


if __name__ == '__main__':
    main()
