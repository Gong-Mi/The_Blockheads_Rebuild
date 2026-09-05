#!/usr/bin/env python3
"""Dependency-free checked-in evidence contracts; not original-ELF execution."""
import json
import re
import struct
import unittest
from recover_gameview_zoom_settle import NATIVE, START, END, CALL_ROUTES, BRANCHES


class ZoomEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((NATIVE / 'gameview_zoom_settle.json').read_text())

    def test_all_calls_in_region_have_one_reviewed_route(self):
        sites = set()
        for line in (NATIVE / 'disasm_gameview_update.txt').read_text().splitlines():
            m = re.search(r'(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+blx?\s', line)
            if m and START <= int(m[1], 16) < END:
                sites.add(int(m[1], 16))
        self.assertEqual(sites, set(CALL_ROUTES))
        self.assertEqual(sites, {int(row['call'], 16) for row in self.report['calls']})
        self.assertEqual(len(self.report['calls']), len(sites))
        self.assertEqual(self.report['call_count'], 30)
        self.assertEqual(self.report['verified_words'], (END-START)//4)
        self.assertFalse(self.report['runtime_verified'])

    def test_every_settling_path_has_distinct_defaults_pair_and_known_notify(self):
        paths = self.report['settling_paths']
        self.assertEqual(len(paths), 10)
        self.assertEqual({p['name'] for p in paths}, {p[0] for p in BRANCHES})
        self.assertEqual(len({p['defaults_get'] for p in paths}), 10)
        self.assertEqual(len({p['defaults_put'] for p in paths}), 10)
        calls = {p['call']: p for p in self.report['calls']}
        for p in paths:
            self.assertEqual(calls[p['defaults_get']]['selector'], 'standardUserDefaults')
            self.assertEqual(calls[p['defaults_put']]['selector'], 'setFloat:forKey:')
            self.assertEqual(calls[p['notify']]['selector'], 'pinchScaleChanged')
            self.assertEqual(calls[p['notify']]['receiver'], 'self')
        self.assertEqual(self.report['defaults_key'], 'pinchScale')

    def test_exact_double_bits_and_source_constant_binding(self):
        source = (NATIVE.parents[1] / 'recovered/zoom_settle.cpp').read_text()
        for literal in self.report['double_literals'].values():
            value = struct.unpack('<d', int(literal['bits'], 16).to_bytes(8, 'little'))[0]
            self.assertEqual(value, literal['value'])
            self.assertEqual(value.hex(), literal['hex_float'])
            if value != 0.0:
                self.assertIn(literal['hex_float'], source)
        immediates = self.report['vfp_immediates']
        self.assertEqual(immediates['0x00926fe0']['value'], 1.25)
        self.assertEqual(immediates['0x009271a0']['value'], 1.75)
        self.assertEqual(immediates['0x00927558']['value'], 2.5)
        self.assertIn('scale < 1.25', source)
        self.assertIn('scale < 1.75', source)
        self.assertIn('scale < 2.5', source)
        self.assertEqual(self.report['double_literals']['0x00926b88']['value'], 0.0)

    def test_tail_and_gate_field_identities(self):
        fields = {r['symbol']: r['offset'] for r in self.report['fields']}
        self.assertEqual(fields, {
            'OBJC_IVAR_$_GameView.isZoomingCameraOut': 357,
            'OBJC_IVAR_$_GameView.pinching': 173,
            'OBJC_IVAR_$_GameView.pinchZooming': 184,
            'OBJC_IVAR_$_GameView.hasPinchVelocity': 172,
            'OBJC_IVAR_$_GameView.lastPinchFactor': 168,
            'OBJC_IVAR_$_GameView.pinchStartScale': 160,
            'OBJC_IVAR_$_GameView.pinchScale': 152,
        })


if __name__ == '__main__':
    unittest.main()
