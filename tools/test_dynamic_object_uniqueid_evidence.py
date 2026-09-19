#!/usr/bin/env python3
"""Contract for the bounded DynamicObject uniqueID getter evidence."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    report = json.loads((NATIVE / 'dynamicobject_uniqueid.json').read_text())
    assert report['method'] == 'DynamicObject -[uniqueID]'
    assert report['imp'] == '0x0083d08c'
    assert report['boundary_end'] == '0x0083d0f0'
    assert report['code_end'] == '0x0083d0e8'
    assert report['verified_words'] == 23
    assert report['pic_base'] == '0x0105faf4'
    assert report['ivar_symbol'] == 'OBJC_IVAR_$_DynamicObject.uniqueID'
    assert report['ivar_offset'] == 40
    assert report['return'] == 'uint64 value copied from self + 40'
    assert report['body_sha256'] == '831fceffcdffd9958d6ecb165b42060c017574d01ac6315eb533442c2e92360d'
    print('dynamicobject-uniqueid-evidence: PASS')

if __name__ == '__main__':
    main()
