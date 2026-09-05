#!/usr/bin/env python3
"""Method-map completeness contracts; CTest separately executes the methods."""
import json
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'reconstruction/reverse-v3/native'


class MethodMapTest(unittest.TestCase):
    def test_every_word_range_and_call_has_one_source_owner(self):
        report=json.loads((NATIVE/'gameview_method.json').read_text())
        phases=report['phases']
        cursor=0x9259c0
        for phase in phases:
            self.assertEqual(int(phase['start'],16),cursor)
            self.assertTrue(phase['source'])
            cursor=int(phase['end_exclusive'],16)
        self.assertEqual(cursor,0x928030)
        self.assertEqual(report['verified_original_words'],(cursor-0x9259c0)//4)
        sites=set(re.findall(r'(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+blx?\s',
                             (NATIVE/'disasm_gameview_update.txt').read_text()))
        self.assertEqual(sites,{r['call'] for r in report['calls']})
        self.assertEqual(len(report['calls']),80)
        self.assertEqual(sum(r['original_selector'] is not None for r in report['calls']),53)
        self.assertEqual(sum(r['original_selector'] is None for r in report['calls']),27)
        self.assertTrue(all(r['execution_binding'] and r['source_owner'] for r in report['calls']))
        self.assertFalse(report['game_adapter_integrated'])
        self.assertFalse(report['original_runtime_differential_verified'])

    def test_executable_dependency_and_projection_ownership(self):
        report=json.loads((NATIVE/'gameview_method.json').read_text())
        self.assertTrue((ROOT/report['source']).is_file())
        cmake=(ROOT/'reconstruction/recovered/CMakeLists.txt').read_text()
        self.assertIn(report['build_target'],cmake)
        for dependency in report['executable_dependencies']:
            self.assertTrue((ROOT/'reconstruction/recovered'/dependency).is_file())
            self.assertIn(dependency,cmake)
        projection=json.loads((NATIVE/'projection_update.json').read_text())
        self.assertEqual(projection['verified_words'],216)
        self.assertEqual(projection['matrix_indices']['11'],'-1')
        self.assertIn('#undef NDEBUG',(ROOT/'tools/test_gameview_update.cpp').read_text())


if __name__=='__main__':
    unittest.main()
