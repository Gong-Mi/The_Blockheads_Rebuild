#!/usr/bin/env python3
"""Contract for the bounded DynamicObject objectType getter evidence."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'


def main():
    report = json.loads((NATIVE / 'dynamicobject_objecttype.json').read_text())
    assert report['method'] == 'DynamicObject -[objectType]'
    assert report['imp'] == '0x008399fc'
    assert report['boundary_end'] == '0x00839a18'
    assert report['verified_words'] == 7
    assert report['return_value'] == 65
    assert report['return'] == 'constant int 0x41; self is not read'
    assert report['body_sha256'] == 'e5bbfad0f755b8445a120e2928f510e831339b26f38e5fd6e1743c8c4f429731'
    print('dynamicobject-objecttype-evidence: PASS')


if __name__ == '__main__':
    main()
