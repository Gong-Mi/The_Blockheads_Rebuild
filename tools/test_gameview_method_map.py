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

    def test_primary_end_touch_static_manifest_and_adapter_boundary(self):
        report=json.loads((NATIVE/'gameview_endtouch.json').read_text())
        self.assertEqual(report['elf_sha256'],'733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7')
        methods={(m['class'],m['selector']):m for m in report['methods']}
        self.assertEqual(set(methods),{('GameView','endTouch:'),('World','endTouch:index:')})
        view=methods[('GameView','endTouch:')]
        self.assertEqual((view['implementation'],view['verified_interval_words'],view['code_words'],view['literal_pool_words']),
                         ('0x0092c3f4',145,133,12))
        self.assertEqual({call['site'] for call in view['calls']},
                         {'0x0092c4a4','0x0092c4e8','0x0092c534','0x0092c5d4'})
        indexed=next(call for call in view['calls'] if call['site']=='0x0092c5d4')
        self.assertIn('index literal 0',indexed['selector_route'])
        self.assertEqual({branch['site'] for branch in view['branches']},
                         {'0x0092c43c','0x0092c464','0x0092c4a8','0x0092c4f4','0x0092c540',
                          '0x0092c564','0x0092c588','0x0092c5d8','0x0092c5dc'})
        # Pinned cell resolution: ivar offsets and selector names re-resolved by the tool.
        self.assertEqual(view['ivar_cells']['secondaryTouchIsActiveInUI']['offset'],508)
        self.assertEqual(view['ivar_cells']['primaryTouchIsActiveInUI']['offset'],496)
        self.assertEqual(set(view['selector_cells']),{'endTouch:','loadComplete','isSimulating','endTouch:index:'})
        world=methods[('World','endTouch:index:')]
        self.assertEqual((world['implementation'],world['verified_interval_words'],world['code_words'],world['literal_pool_words']),
                         ('0x005b3430',33,31,2))
        self.assertEqual([call['site'] for call in world['calls']],['0x005b34a0'])
        self.assertIn('wasCancelled',world['calls'][0]['selector_route'])
        self.assertEqual(list(world['selector_cells']),['doEndTouch:wasCancelled:index:'])
        self.assertFalse(report['replacement_boundary']['apk_integration'])
        self.assertFalse(report['replacement_boundary']['original_runtime_differential'])
        table=(NATIVE/'libApplication_objc_methods.tsv').read_text()
        self.assertIn(chr(9).join(['0x005b3308','World','instance','doEndTouch:wasCancelled:index:']),table)
        self.assertTrue((ROOT/'reconstruction/recovered/gameview_end_touch.cpp').is_file())
        self.assertTrue((ROOT/'reconstruction/recovered/world_end_touch.cpp').is_file())
        self.assertTrue((ROOT/'tools/test_gameview_endtouch.cpp').is_file())
        cmake=(ROOT/'reconstruction/recovered/CMakeLists.txt').read_text()
        self.assertIn('test_gameview_endtouch',cmake)
        self.assertIn('gameview_end_touch.cpp',cmake)
        self.assertIn('world_end_touch.cpp',cmake)

    def test_primary_cancel_touch_static_manifest_and_tail_merge(self):
        report=json.loads((NATIVE/'gameview_canceltouch_batch.json').read_text())
        self.assertEqual(report['elf_sha256'],'733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7')
        self.assertTrue(report['world_forwarding_pair_tail_merge'])
        methods={(m['class'],m['selector']):m for m in report['methods']}
        self.assertEqual(set(methods),{('GameView','cancelTouch:'),('World','cancelTouch:index:')})
        view=methods[('GameView','cancelTouch:')]
        self.assertEqual((view['implementation'],view['verified_interval_words'],view['code_words'],view['literal_pool_words']),
                         ('0x0092c638',153,140,13))
        self.assertEqual({call['site'] for call in view['calls']},
                         {'0x0092c6e8','0x0092c72c','0x0092c778','0x0092c818'})
        menu=next(call for call in view['calls'] if call['site']=='0x0092c6e8')
        self.assertIn('endTouch:',menu['selector_route'])  # menu receives END, not cancel
        self.assertEqual({branch['site'] for branch in view['branches']},
                         {'0x0092c680','0x0092c6a8','0x0092c6ec','0x0092c738','0x0092c784',
                          '0x0092c7a8','0x0092c7cc','0x0092c83c'})
        self.assertEqual(view['ivar_cells']['startTouchHasntMoved']['offset'],486)
        world=methods[('World','cancelTouch:index:')]
        self.assertEqual((world['implementation'],world['verified_interval_words'],world['code_words'],world['literal_pool_words']),
                         ('0x005b33ac',33,31,2))
        self.assertEqual([call['site'] for call in world['calls']],['0x005b341c'])
        self.assertIn('wasCancelled literal 1',world['calls'][0]['selector_route'])
        self.assertFalse(report['replacement_boundary']['apk_integration'])
        table=(NATIVE/'libApplication_objc_methods.tsv').read_text()
        self.assertIn(chr(9).join(['0x005b33ac','World','instance','cancelTouch:index:']),table)
        self.assertTrue((ROOT/'reconstruction/recovered/gameview_cancel_touch.cpp').is_file())
        self.assertTrue((ROOT/'tools/test_gameview_canceltouch.cpp').is_file())
        cmake=(ROOT/'reconstruction/recovered/CMakeLists.txt').read_text()
        self.assertIn('test_gameview_canceltouch',cmake)

    def test_secondary_end_cancel_mirror_pair(self):
        report=json.loads((NATIVE/'gameview_secondarytouch.json').read_text())
        self.assertEqual(report['elf_sha256'],'733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7')
        methods={(m['class'],m['selector']):m for m in report['methods']}
        self.assertEqual(set(methods),{('GameView','endSecondaryTouch:'),('GameView','cancelSecondaryTouch:')})
        end=methods[('GameView','endSecondaryTouch:')]
        self.assertEqual((end['implementation'],end['verified_interval_words'],end['code_words'],end['literal_pool_words']),
                         ('0x0092cdd8',114,104,10))
        self.assertEqual({call['site'] for call in end['calls']},
                         {'0x0092ce5c','0x0092cea8','0x0092cf48'})
        fwd=next(call for call in end['calls'] if call['site']=='0x0092cf48')
        self.assertIn('endTouch:index:',fwd['selector_route'])
        self.assertIn('index literal 1',fwd['selector_route'])
        self.assertEqual({branch['site'] for branch in end['branches']},
                         {'0x0092ce1c','0x0092ce68','0x0092ceb4','0x0092ced8','0x0092cefc','0x0092cf4c'})
        self.assertEqual(end['ivar_cells']['secondaryTouchStarted']['offset'],498)
        cancel=methods[('GameView','cancelSecondaryTouch:')]
        self.assertEqual((cancel['implementation'],cancel['verified_interval_words'],cancel['code_words'],cancel['literal_pool_words']),
                         ('0x0092cfa0',122,111,11))
        fwdc=next(call for call in cancel['calls'] if call['route']=='bl objc_msgSend@plt')
        self.assertIn('cancelTouch:index:',fwdc['selector_route'])
        self.assertIn('index literal 1',fwdc['selector_route'])
        self.assertEqual(cancel['ivar_cells']['secondaryStartTouchHasntMoved']['offset'],497)
        # Mirror claim: both bodies share the SAME World selref SLOT as the
        # primary pair's indexed forwards (endTouch:index: slot 0xe836bc,
        # cancelTouch:index: slot 0xe836c0).
        #
        # The slot is the claim; the load CELL legitimately differs, because
        # the two bodies are different methods. Verified against the pinned
        # ELF: endTouch:index:'s cell 0x0092c630 sits in GameView -endTouch:
        # (IMP 0x0092c3f4) and 0x0092cf98 sits in GameView -endSecondaryTouch:
        # (IMP 0x0092cdd8), while both cells hold the same literal addend
        # 0xffe23bc8 for the shared slot. Comparing whole dicts asserted the
        # wrong invariant and failed on the two candidates.
        primary=json.loads((NATIVE/'gameview_endtouch.json').read_text())
        pend=next(m for m in primary['methods'] if m['selector']=='endTouch:')
        self.assertEqual(pend['selector_cells']['endTouch:index:']['slot'],
                         end['selector_cells']['endTouch:index:']['slot'])
        pcancel=json.loads((NATIVE/'gameview_canceltouch_batch.json').read_text())
        pcan=next(m for m in pcancel['methods'] if m['selector']=='cancelTouch:')
        self.assertEqual(pcan['selector_cells']['cancelTouch:index:']['slot'],
                         cancel['selector_cells']['cancelTouch:index:']['slot'])
        self.assertFalse(report['replacement_boundary']['apk_integration'])
        self.assertTrue((ROOT/'reconstruction/recovered/gameview_secondary_touch.cpp').is_file())
        self.assertTrue((ROOT/'tools/test_gameview_secondarytouch.cpp').is_file())


if __name__=='__main__':
    unittest.main()
