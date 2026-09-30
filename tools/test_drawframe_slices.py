#!/usr/bin/env python3
import unittest
from recover_drawframe_slices import verify_disassembly, SLICES


class SliceGateTest(unittest.TestCase):
    def test_exact_bytes_and_coverage(self):
        class Memory:
            def word(self, address):
                return {0x10: 0xe1a00000, 0x14: 0xe12fff1e}.get(address)
        text = '0x00000010 0000a0e1 mov r0, r0\n0x00000014 1eff2fe1 bx lr\n'
        self.assertEqual(verify_disassembly(Memory(), text, 0x10, 0x18), 2)
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            verify_disassembly(Memory(), text.replace('0000a0e1', '0100a0e1'), 0x10, 0x18)
        with self.assertRaisesRegex(ValueError, 'exactly cover'):
            verify_disassembly(Memory(), text.splitlines()[0], 0x10, 0x18)
        with self.assertRaisesRegex(ValueError, 'exactly cover'):
            verify_disassembly(Memory(), text + text, 0x10, 0x18)

    def test_initopengl_map_covers_every_indirect_call(self):
        import re
        from recover_gameview_initopengl import CALL_LITERALS, NATIVE
        text = (NATIVE / 'disasm_gameview_initopengl.txt').read_text()
        sites = {int(a, 16) for a in re.findall(r'(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+blx\s', text)}
        self.assertEqual(sites, set(CALL_LITERALS))
        self.assertEqual(len(sites), 23)
        self.assertEqual(len(re.findall(r'\sbl sym.imp.__wrap_gl', text)), 7)

    def test_vfp_immediate_is_decoded_from_bits_not_disassembly_label(self):
        from recover_gameview_update_boundary import expand_vfp_immediate
        for width in (32, 64):
            self.assertEqual(expand_vfp_immediate(0x24, width), 10.0)
            self.assertEqual(expand_vfp_immediate(0x70, width), 1.0)
            self.assertEqual(expand_vfp_immediate(0x08, width), 3.0)
            self.assertEqual(expand_vfp_immediate(0xa4, width), -10.0)
        with self.assertRaises(ValueError):
            expand_vfp_immediate(256, 32)

    def test_update_inventory_includes_direct_and_stret_calls(self):
        import json
        import re
        from recover_gameview_update_boundary import NATIVE
        text = (NATIVE / 'disasm_gameview_update.txt').read_text()
        report = json.loads((NATIVE / 'gameview_update_boundary.json').read_text())
        sites = set(re.findall(r'(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+blx?\s', text))
        self.assertEqual(sites, {row['call'] for row in report['calls']})
        self.assertEqual(len(report['calls']), len(sites))
        self.assertEqual(report['call_count'], 80)
        self.assertEqual(report['direct_call_count'], 39)
        self.assertEqual(report['indirect_call_count'], 41)
        self.assertEqual(report['reviewed_selector_route_count'], sum(row['selector_reviewed'] is not None for row in report['calls']))

    def test_translation_return_evidence_contract(self):
        import json
        import struct
        from recover_gameview_update_boundary import NATIVE
        report = json.loads((NATIVE / 'gameview_update_boundary.json').read_text())
        calls = {r['call']: r['selector_reviewed'] for r in report['calls']}
        self.assertEqual(calls['0x0092670c'], 'translatingToGoal')
        self.assertEqual(calls['0x00926764'], 'translation')
        self.assertEqual(calls['0x00926a44'], 'setTranslation:')
        fields = {r['literal']: (r['symbol'], r['offset']) for r in report['fields']}
        self.assertEqual(fields['0x0092771c'], ('OBJC_IVAR_$_GameView.windowInfo', 208))
        literals = report['translation_return_literals']
        f32 = lambda x: struct.unpack('<f', struct.pack('<f', x))[0]
        self.assertEqual(literals, {'world_span': 1024.0, 'lane3_multiplier': f32(0.025),
                                   'snap_epsilon': f32(0.01), 'bias_double': f32(0.01),
                                   'scale_limit_numerator': 40960.0})
        self.assertNotEqual(literals['bias_double'], 0.01)
        immediates = {r['instruction']: r['value'] for r in report['vfp_constants']}
        for address in ('0x00926850', '0x0092696c'):
            self.assertEqual(immediates[address], 10.0)

    def test_reviewed_paths_have_unique_call_sites(self):
        self.assertEqual(len(SLICES), 11)
        self.assertEqual(len({row[0] for row in SLICES}), 11)
        # This validates the reviewed map schema, not its runtime semantics.
        self.assertTrue(all(receiver and route for _, _, _, receiver, route in SLICES))


if __name__ == '__main__':
    unittest.main()
