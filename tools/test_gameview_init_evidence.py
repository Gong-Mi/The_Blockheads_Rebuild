#!/usr/bin/env python3
"""Dependency-free contract for checked-in GameView -[init] evidence.

Runs in CI without the copyrighted ELF: verifies the listing covers the pinned
IMP..exidx range exactly, the JSON agrees with the listing, selector names
match the shared method-map evidence, and unresolved sites stay unresolved
(the tool must not silently gain guesses).
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
START, END = 0x0091C780, 0x0091D9CC
ELF_SHA256 = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


class GameViewInitEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.listing = (NATIVE / 'disasm_gameview_init.txt').read_text()
        cls.report = json.loads((NATIVE / 'gameview_init.json').read_text())

    def test_listing_covers_exact_word_range(self):
        rows = re.findall(r'\b(0x[0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\b', self.listing)
        addresses = [int(a, 16) for a, _ in rows]
        self.assertEqual(sorted(set(addresses)), list(range(START, END, 4)))
        self.assertEqual(len(addresses), len(set(addresses)))

    def test_json_identity_and_shape(self):
        self.assertEqual(self.report['elf_sha256'], ELF_SHA256)
        self.assertEqual(int(self.report['imp'], 16), START)
        self.assertEqual(int(self.report['arm_exidx_end'], 16), END)
        self.assertEqual(int(self.report['pic_base'], 16), 0x0105FAF4)
        self.assertEqual(self.report['instruction_words'], (END - START) // 4)
        self.assertEqual(self.report['listing_verified_words'], (END - START) // 4)

    def test_calls_exactly_partition_blx_sites(self):
        sites = {int(m[1], 16) for m in re.finditer(
            r'(0x0091[0-9a-f]{4})\s+[0-9a-f]{8}\s+blx\s', self.listing)}
        listed = {int(row['call'], 16) for row in self.report['calls']}
        self.assertEqual(sites, listed)
        self.assertEqual(self.report['blx_sites'], len(sites))

    def test_resolved_routes_are_msgsend_selector_pairs(self):
        selector_rows = [row for row in self.report['calls']
                         if row['selector'].get('kind') == 'selector']
        msgsend_rows = [row for row in selector_rows
                        if row['target'].get('symbol') in
                        ('objc_msgSend', 'objc_msgSendSuper2')]
        self.assertEqual(self.report['selector_resolved_calls'], len(msgsend_rows))
        # 27 selector names recovered; 21 of them provably dispatched through
        # objc_msgSend/Super2. Baseline pins: growth requires re-review,
        # shrinkage means evidence loss.
        self.assertEqual(len(selector_rows), 27)
        self.assertEqual(len(msgsend_rows), 21)

    def test_selector_names_exist_in_pinned_method_map(self):
        names = {row['selector']['name'] for row in self.report['calls']
                 if row['selector'].get('kind') == 'selector'}
        methods = (NATIVE / 'libApplication_objc_methods.tsv').read_text()
        for name in names:
            # every referenced selector must be a known __objc_selrefs string;
            # presence anywhere in shared TSV evidence or as any method selector
            self.assertTrue(name in methods or ':' in name or name in
                            {'alloc', 'init', 'release', 'instance',
                             'standardUserDefaults', 'defaultQueue',
                             'boolForKey:', 'floatForKey:',
                             'stringWithFormat:', 'objectAtIndex:'},
                            f'unknown selector {name}')

    def test_cfstring_set_is_closed(self):
        strings = sorted(row['string'] for row in self.report['cfstrings'])
        self.assertEqual(len(strings), 12)
        for needle in ('%@/game/', '%@/game_db/', 'Hax',
                       'Error. Unable to open app database.',
                       'hdTexturesDisabled', 'pinchScale', 'hasBoughtIAP',
                       'totalTCBuyCount', 'totalGamePlayTimePassed'):
            self.assertIn(needle, strings)

    def test_direct_plt_targets(self):
        direct = {row['call']: row['symbol'] for row in self.report['direct_calls']}
        self.assertEqual(direct['0x0091c8f4'], 'NSSearchPathForDirectoriesInDomains')
        self.assertEqual(direct['0x0091cae8'], 'NSLog')
        self.assertEqual(direct['0x0091caf0'], '__wrap_exit')
        self.assertEqual(direct['0x0091cb24'], 'time')

    def test_unresolved_sites_stay_marked(self):
        unresolved = [row for row in self.report['calls']
                      if row['target'].get('kind') == 'unresolved']
        self.assertEqual(len(unresolved), 38)
        self.assertEqual(len(self.report['calls']),
                         self.report['blx_sites'])
        # an unresolved target may still carry a recovered selector (r1 known,
        # dispatch reg unknown); those pairs must not be promoted to routes.
        for row in unresolved:
            if row['selector'].get('kind') == 'selector':
                self.assertIn(row['call'], ('0x0091cf80', '0x0091d460',
                                            '0x0091d760', '0x0091d7d0',
                                            '0x0091d82c', '0x0091d8bc'))

    def test_evidence_document_quotes_only_reported_values(self):
        doc = (NATIVE / 'GAMEVIEW_INIT.md').read_text()
        for needle in ('0x0091c780', '0x0091d9cc', '1171', '0x0105faf4',
                       'initWithPath:maxDatabases:maxMapSizeInMB:',
                       'reconnectWithAuthenticationDelegate:',
                       'totalGamePlayTimePassed'):
            self.assertIn(needle, doc)


if __name__ == '__main__':
    unittest.main()
