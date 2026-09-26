#!/usr/bin/env python3
"""Static contract and negative controls for batch 2h getSaveDict key pairings."""
import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

EXPECTED_LISTING_SHA256 = {
    'disasm_tulipplant_getsavedict.txt': '02751712c22382848a87ae8d4a3abbd518d7ef6479a11d4b4244b81a4bccff29',
    'disasm_steamtrain_getsavedict.txt': 'b53882a4019a9d5d50321ad77be4ee058c9b79de6bc60811ca316fd6ece4fc19',
    'disasm_ownershipsign_getsavedict.txt': '03db3baafaf27aa82b07bd32b69c6a69c78512e3dff6f3846c83efdd4e066ee7',
    'disasm_cactustree_getsavedict.txt': '93892c30515e781b0ee30aa3706574ba102cab11347ee0f86692a8440e95e00b',
}

EXPECTED_CALLS = {
    'TulipPlant': ['0x009a18a8', '0x009a19c0', '0x009a19e4', '0x009a1a20', '0x009a1a44',
                   '0x009a1a80', '0x009a1aa4', '0x009a1ae0', '0x009a1b04'],
    'SteamTrain': ['0x00d18ed8', '0x00d18ff0', '0x00d19014', '0x00d19050', '0x00d19074',
                   '0x00d190b0', '0x00d190d4', '0x00d19110', '0x00d19134'],
    'OwnershipSign': ['0x00a35938', '0x00a35a04', '0x00a35a3c', '0x00a35ad8', '0x00a35afc',
                      '0x00a35b98', '0x00a35bbc'],
    'CactusTree': ['0x00b5377c', '0x00b538b4', '0x00b538d8', '0x00b53914', '0x00b53938',
                   '0x00b53974', '0x00b53998', '0x00b539d4', '0x00b539f8'],
}

EXPECTED_BRANCHES = {
    'TulipPlant': [],
    'SteamTrain': [],
    'OwnershipSign': ['0x00a3596c', '0x00a35994', '0x00a35a60', '0x00a35b20'],
    'CactusTree': [],
}


def get_body_bytes(text):
    pairs = re.findall(r'^\s+(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s', text, re.MULTILINE)
    return b''.join(bytes.fromhex(w) for _, w in pairs)


def verify_contract(report, read_text_fn=None):
    if read_text_fn is None:
        read_text_fn = lambda p: p.read_text()
    assert report['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    cls = {c['class']: c for c in report['classes']}
    assert list(cls) == ['TulipPlant', 'SteamTrain', 'OwnershipSign', 'CactusTree']

    for name, expected_sha in EXPECTED_LISTING_SHA256.items():
        text = read_text_fn(NATIVE / name)
        raw = get_body_bytes(text)
        actual_sha = hashlib.sha256(raw).hexdigest()
        assert actual_sha == expected_sha, f'{name}: body sha256 mismatch'

    for class_name, expected_calls in EXPECTED_CALLS.items():
        c = cls[class_name]
        assert c.get('call_sites') == expected_calls, f'{class_name}: call sites mismatch'
        assert c.get('branch_sites') == EXPECTED_BRANCHES[class_name], f'{class_name}: branch sites mismatch'
        assert c.get('body_sha256') == EXPECTED_LISTING_SHA256[f'disasm_{class_name.lower()}_getsavedict.txt']

    tp = cls['TulipPlant']
    assert [k['key'] for k in tp['keys']] == ['availableFood', 'colorGenes', 'mixGenes', 'mateColorGenes']
    assert [k['ivar_offset'] for k in tp['keys']] == [100, 112, 114, 116]
    assert tp['keys'][0]['conversion'] == 'numberWithFloat:'

    st = cls['SteamTrain']
    assert [k['key'] for k in st['keys']] == ['fuelFraction', 'hasFuel', 'goingRight', 'stopped']
    assert [k['ivar_offset'] for k in st['keys']] == [260, 268, 252, 325]
    assert st['keys'][0]['conversion'] == 'numberWithFloat:'
    assert all(k['conversion'] == 'numberWithBool:' for k in st['keys'][1:])

    os_ = cls['OwnershipSign']
    assert [k['key'] for k in os_['keys']] == ['landOwnerID', 'landOwnerName', 'w', 'h']
    assert os_['keys'][0]['conversion'] == 'direct_object'
    assert os_['keys'][0]['ivar'] == 'OBJC_IVAR_$_OwnershipSign.landOwnerID'
    assert os_['keys'][0]['ivar_offset'] == 124
    assert os_['keys'][2]['ivar'] == 'OBJC_IVAR_$_OwnershipSign.widthRadius'
    assert os_['keys'][3]['ivar'] == 'OBJC_IVAR_$_OwnershipSign.heightRadius'

    ct = cls['CactusTree']
    assert [k['key'] for k in ct['keys']] == ['splitHeightA', 'splitHeightB', 'splitDirection', 'availableFood']
    assert [k['ivar_offset'] for k in ct['keys']] == [136, 140, 144, 148]
    assert ct['keys'][2]['conversion'] == 'numberWithBool:'
    assert ct['keys'][3]['conversion'] == 'numberWithFloat:'
    return True


class TestB2HEvidenceIntegrity(unittest.TestCase):
    def setUp(self):
        self.report = json.loads((NATIVE / 'subclass_savedict_keys_b2h.json').read_text())

    def test_positive_contract(self):
        self.assertTrue(verify_contract(self.report))

    def test_negative_zeroed_instruction_caught(self):
        def fake_read(p):
            t = p.read_text()
            if p.name == 'disasm_tulipplant_getsavedict.txt':
                t = re.sub(r'(0x009a19c0\s+)[0-9a-f]{8}', r'\g<1>00000000', t)
            return t
        with self.assertRaises(AssertionError):
            verify_contract(self.report, read_text_fn=fake_read)

    def test_negative_swapped_call_site_caught(self):
        rep = json.loads(json.dumps(self.report))
        rep['classes'][0]['call_sites'][0], rep['classes'][0]['call_sites'][1] = (
            rep['classes'][0]['call_sites'][1], rep['classes'][0]['call_sites'][0]
        )
        with self.assertRaises(AssertionError):
            verify_contract(rep)

    def test_negative_wrong_ivar_offset_caught(self):
        rep = json.loads(json.dumps(self.report))
        rep['classes'][0]['keys'][0]['ivar_offset'] = 999
        with self.assertRaises(AssertionError):
            verify_contract(rep)

    def test_negative_extraneous_call_caught(self):
        rep = json.loads(json.dumps(self.report))
        rep['classes'][0]['call_sites'].append('0x009a1b99')
        with self.assertRaises(AssertionError):
            verify_contract(rep)


def main():
    report = json.loads((NATIVE / 'subclass_savedict_keys_b2h.json').read_text())
    verify_contract(report)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestB2HEvidenceIntegrity)
    runner = unittest.TextTestRunner(verbosity=1)
    res = runner.run(suite)
    if not res.wasSuccessful():
        raise SystemExit(1)
    print('subclass-savedict-keys-b2h-evidence: PASS')


if __name__ == '__main__':
    main()
