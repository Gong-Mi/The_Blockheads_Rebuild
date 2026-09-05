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

    def test_reviewed_paths_have_unique_call_sites(self):
        self.assertEqual(len(SLICES), 11)
        self.assertEqual(len({row[0] for row in SLICES}), 11)
        # This validates the reviewed map schema, not its runtime semantics.
        self.assertTrue(all(receiver and route for _, _, _, receiver, route in SLICES))


if __name__ == '__main__':
    unittest.main()
