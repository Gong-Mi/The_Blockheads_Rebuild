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
    def test_primary_move_touch_static_manifest_and_adapter_boundary(self):
        report=json.loads((NATIVE/'gameview_movetouch.json').read_text())
        self.assertEqual(report['elf_sha256'],'733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7')
        methods={(m['class'],m['selector']):m for m in report['methods']}
        self.assertEqual(set(methods),{('GameView','moveTouch:'),('World','moveTouch:index:')})
        view=methods[('GameView','moveTouch:')]
        self.assertEqual((view['implementation'],view['verified_interval_words'],view['code_words'],view['literal_pool_words']),
                         ('0x0092c148',171,158,13))
        self.assertEqual({call['site'] for call in view['calls']},
                         {'0x0092c1f8','0x0092c23c','0x0092c288','0x0092c304'})
        indexed=next(call for call in view['calls'] if call['site']=='0x0092c304')
        self.assertIn('index literal 0',indexed['selector_route'])
        self.assertEqual({branch['site'] for branch in view['branches']},
                         {'0x0092c190','0x0092c1b8','0x0092c1fc','0x0092c248','0x0092c294',
                          '0x0092c2b8','0x0092c348','0x0092c38c','0x0092c3b0','0x0092c3b4'})
        world=methods[('World','moveTouch:index:')]
        self.assertEqual((world['implementation'],world['verified_interval_words'],world['code_words'],world['literal_pool_words']),
                         ('0x005b3278',36,33,3))
        self.assertEqual([call['site'] for call in world['calls']],['0x005b32f0'])
        self.assertFalse(report['replacement_boundary']['apk_integration'])
        self.assertFalse(report['replacement_boundary']['original_runtime_differential'])
        table=(NATIVE/'libApplication_objc_methods.tsv').read_text()
        self.assertIn(chr(9).join(['0x00ad8048','UIManager','instance','moveTouch:index:']),table)
        self.assertTrue((ROOT/'reconstruction/recovered/gameview_move_touch.cpp').is_file())
        self.assertTrue((ROOT/'reconstruction/recovered/world_move_touch.cpp').is_file())
        self.assertTrue((ROOT/'tools/test_gameview_movetouch.cpp').is_file())
        cmake=(ROOT/'reconstruction/recovered/CMakeLists.txt').read_text()
        self.assertIn('test_gameview_movetouch',cmake)
        self.assertIn('gameview_move_touch.cpp',cmake)
        self.assertIn('world_move_touch.cpp',cmake)


if __name__=='__main__':
    unittest.main()
