#!/usr/bin/env python3
"""Regression test for the automated ARM32 getSaveDict feature tracer.

Exercises trace_savedict_arm_features against original ARM32 binaries.
Verifies automated value-source detection across 8 distinct world object classes:
Torch, Sign, ArtificialLight, FreeBlock, Door, Ladder, Bed, TradePortal.
"""
import unittest
from pathlib import Path

ELF_PATH = Path('/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so')


class TestTraceSaveDictARMFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ELF_PATH.exists():
            raise unittest.SkipTest('original ELF not present on host')
        import trace_savedict_arm_features as tracer
        cls.tracer = tracer
        cls.uc = tracer.create_emulator(ELF_PATH)

    def test_door_features(self):
        res = self.tracer.trace_savedict(self.uc, 0x00769DC8, 0x0076A084)
        self.assertTrue(res['return_equals_super_dict'])
        keys = {k['key']: k for k in res['keys']}
        self.assertEqual(list(keys.keys()), ['itemType', 'blocked', 'ironPlaceClientID', 'ownerID'])
        self.assertEqual(keys['itemType']['offset'], 64)
        self.assertEqual(keys['itemType']['width'], 32)
        self.assertEqual(keys['blocked']['offset'], 68)
        self.assertEqual(keys['blocked']['width'], 16)
        self.assertEqual(keys['ironPlaceClientID']['offset'], 72)
        self.assertEqual(keys['ironPlaceClientID']['kind'], 'direct_object')
        self.assertEqual(keys['ownerID']['offset'], 36)
        self.assertEqual(keys['ownerID']['kind'], 'direct_object')
        self.assertEqual(len(res['call_sites']), 7)
        self.assertEqual(len(res['branch_sites']), 2)

    def test_freeblock_features(self):
        res = self.tracer.trace_savedict(self.uc, 0x00629804, 0x0062A4B8)
        self.assertTrue(res['return_equals_super_dict'])
        keys = {k['key']: k for k in res['keys']}
        self.assertIn('bounceTimer', keys)
        self.assertEqual(keys['bounceTimer']['offset'], 68)
        self.assertEqual(keys['bounceTimer']['conversion'], 'numberWithFloat:')
        self.assertIn('fallSpeed', keys)
        self.assertEqual(keys['fallSpeed']['offset'], 72)
        self.assertEqual(keys['fallSpeed']['conversion'], 'numberWithFloat:')
        self.assertEqual(keys['floatPos[VX]']['offset'], 24)
        self.assertEqual(keys['floatPos[VY]']['offset'], 28)
        self.assertEqual(keys['itemType']['offset'], 56)
        self.assertEqual(keys['dataA']['offset'], 60)
        self.assertEqual(keys['dataA']['width'], 16)
        self.assertEqual(keys['dataB']['offset'], 62)
        self.assertEqual(keys['dataB']['width'], 16)
        self.assertEqual(keys['creationTime']['offset'], 80)
        self.assertEqual(keys['creationTime']['conversion'], 'numberWithDouble:')
        self.assertEqual(keys['dynamicObjectSaveDict']['offset'], 140)
        self.assertEqual(keys['dynamicObjectSaveDict']['kind'], 'direct_object')
        self.assertEqual(len(res['call_sites']), 40)
        self.assertEqual(len(res['branch_sites']), 15)

    def test_ladder_features(self):
        res = self.tracer.trace_savedict(self.uc, 0x00AAE2AC, 0x00AAE518)
        self.assertTrue(res['return_equals_super_dict'])
        keys = {k['key']: k for k in res['keys']}
        self.assertEqual(list(keys.keys()), ['itemType', 'paintColor', 'ownerID'])
        self.assertEqual(keys['itemType']['offset'], 56)
        self.assertEqual(keys['paintColor']['offset'], 60)
        self.assertEqual(keys['paintColor']['width'], 16)
        self.assertEqual(keys['paintColor']['conversion'], 'numberWithUnsignedInt:')
        self.assertEqual(keys['ownerID']['offset'], 36)

    def test_bed_features(self):
        res = self.tracer.trace_savedict(self.uc, 0x00D410CC, 0x00D41334)
        self.assertTrue(res['return_equals_super_dict'])
        keys = {k['key']: k for k in res['keys']}
        self.assertEqual(list(keys.keys()), ['itemType', 'beddingColor'])
        self.assertEqual(keys['itemType']['offset'], 100)
        self.assertEqual(keys['beddingColor']['offset'], 104)
        self.assertEqual(keys['beddingColor']['width'], 16)

    def test_trade_portal_features(self):
        res = self.tracer.trace_savedict(self.uc, 0x00D39460, 0x00D39794)
        self.assertTrue(res['return_equals_super_dict'])
        keys = {k['key']: k for k in res['keys']}
        self.assertEqual(list(keys.keys()), ['localPriceOffsets', 'level', 'lightDict'])
        self.assertEqual(keys['localPriceOffsets']['offset'], 128)
        self.assertEqual(keys['localPriceOffsets']['kind'], 'direct_object')
        self.assertEqual(keys['level']['offset'], 132)
        self.assertEqual(keys['lightDict']['kind'], 'nested_getSaveDict')


def main():
    if not ELF_PATH.exists():
        print('trace-savedict-arm-features: SKIP (original ELF not present)')
        return
    suite = unittest.TestLoader().loadTestsFromTestCase(TestTraceSaveDictARMFeatures)
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    if not res.wasSuccessful():
        raise SystemExit(1)
    print('trace-savedict-arm-features: PASS (Door, FreeBlock, Ladder, Bed, TradePortal)')


if __name__ == '__main__':
    main()
