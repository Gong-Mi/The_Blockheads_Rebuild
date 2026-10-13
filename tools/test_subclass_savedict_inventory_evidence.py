#!/usr/bin/env python3
"""Static contract for the subclass getSaveDict override inventory batch."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

FORWARDERS = ['CherryTree', 'ClownFish', 'CoconutTree', 'CoffeeTree', 'Dodo',
              'FreightCar', 'HandCar', 'LimeTree', 'MangoTree', 'MapleTree',
              'Mirror', 'OrangeTree', 'PassengerCar', 'Scorpion', 'Shark']

def main():
    report = json.loads((NATIVE / 'subclass_savedict_inventory.json').read_text())
    assert report['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert report['pic_base'] == '0x0105faf4'
    assert report['forwarder_count'] == 15
    assert report['tail_dispatch_count'] == 2
    assert report['forwarder_template_words'] == 27
    overrides = {o['class']: o for o in report['overrides']}
    assert len(overrides) == 17
    for cls in FORWARDERS:
        o = overrides[cls]
        assert o['style'] == 'super_forward' and o['code_words'] == 27
        assert o['dispatch'] == 'objc_msgSendSuper2' and o['selector'] == 'getSaveDict'
        assert o['route'] == '[super getSaveDict] passthrough'
        assert o['class_struct'].startswith('0x00e9') or o['class_struct'].startswith('0x00e8')
    bh = overrides['Blockhead']
    assert bh['style'] == 'tail_dispatch' and bh['code_words'] == 17
    assert bh['selector'] == 'getSaveDictIncludingWorkbenchOrInterationObject:'
    assert bh['route'] == '[self getSaveDictIncludingWorkbenchOrInterationObject:NO]'
    ch = overrides['Chest']
    assert ch['style'] == 'tail_dispatch' and ch['code_words'] == 30
    assert ch['selector'] == 'getSaveDictIncludingInventory:'
    assert ch['argument_ivar'] == {'symbol': 'OBJC_IVAR_$_Chest.chestType',
                                   'offset': 108, 'comparison': '== 4'}
    imps = [o['imp'] for o in report['overrides']]
    assert len(set(imps)) == 17
    print('subclass-savedict-inventory-evidence: PASS')

if __name__ == '__main__':
    main()
