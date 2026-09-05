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

    def test_reviewed_paths_have_unique_call_sites(self):
        self.assertEqual(len(SLICES), 11)
        self.assertEqual(len({row[0] for row in SLICES}), 11)
        # This validates the reviewed map schema, not its runtime semantics.
        self.assertTrue(all(receiver and route for _, _, _, receiver, route in SLICES))


if __name__ == '__main__':
    unittest.main()
