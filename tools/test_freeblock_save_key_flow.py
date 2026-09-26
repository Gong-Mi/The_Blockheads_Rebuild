#!/usr/bin/env python3
"""Synthetic ARM regressions for tracer honesty, not original-game semantics."""
import contextlib
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import freeblock_save_key_flow as flow


class Memory:
    def __init__(self, words, start=0x1000):
        self.data = b''.join(w.to_bytes(4, 'little') for w in words)
        self.start = start
        self.imports = {}
        self.selectors = {}

    def offset(self, address, size):
        offset = address - self.start
        return offset if 0 <= offset and offset + size <= len(self.data) else None

    def word(self, address):
        off = self.offset(address, 4)
        return None if off is None else int.from_bytes(self.data[off:off + 4], 'little')


class BoundedCandidateTrace(unittest.TestCase):
    def run_trace(self, words, start=0x1000, end=None):
        if end is None:
            end = start + len(words) * 4
        memory = Memory(words, start)
        output = io.StringIO()
        with patch.object(flow, 'ELFMemory', return_value=memory):
            with contextlib.redirect_stdout(output):
                flow.main(Path('synthetic-not-an-elf'), start, end)
        return json.loads(output.getvalue())

    def test_requested_end_excludes_adjacent_call(self):
        # blx r3; blx r3. Only the first word belongs to this method.
        result = self.run_trace([0xe12fff33, 0xe12fff33], end=0x1004)
        self.assertEqual(result['total_blx_bl_sites'], 1)

    def test_unresolved_blx_is_not_fabricated_msgsend(self):
        result = self.run_trace([0xe12fff33])
        sites = result.get('sites', [])
        self.assertEqual(len(sites), 1, 'all sites, including unknowns, must remain visible')
        self.assertIsNone(sites[0]['dispatch'])
        self.assertEqual(result['resolved_sites'], [])

    def test_ble_is_a_branch_not_a_link_call(self):
        # ble 0x1008; blx r3. Do not confuse the "bl" prefix with BL.
        result = self.run_trace([0xda000000, 0xe12fff33])
        self.assertEqual(result['total_blx_bl_sites'], 1)
        self.assertEqual(result.get('branch_sites'), [
            {'site': '0x00001000', 'mn': 'ble', 'ops': '#0x1008'}])
        self.assertEqual(result.get('analysis_kind'), 'linear-candidates-only')
        self.assertIs(result.get('conditional_paths_evaluated'), False)

    def test_known_import_still_resolves(self):
        # PC-relative literal -> add pc -> GOT load -> blx r3.
        memory = Memory([0xe59f3008, 0xe08f3003, 0xe5933000, 0xe12fff33, 0xff4])
        memory.imports[0x2000] = 'objc_msgSend'
        output = io.StringIO()
        with patch.object(flow, 'ELFMemory', return_value=memory):
            with contextlib.redirect_stdout(output):
                flow.main(Path('synthetic'), 0x1000, 0x1010)
        result = json.loads(output.getvalue())
        self.assertEqual(result['sites'][0]['dispatch'], 'objc_msgSend')

    def test_decode_gap_does_not_silently_truncate_census(self):
        with self.assertRaises(ValueError):
            self.run_trace([0xe12fff33, 0xffffffff, 0xe12fff33])

    def test_rejects_empty_or_reversed_interval(self):
        for end in (0x1000, 0x0ffc):
            with self.subTest(end=end), self.assertRaises(ValueError):
                self.run_trace([0xe12fff33], end=end)

    def test_rejects_partial_arm_word(self):
        with self.assertRaises(ValueError):
            self.run_trace([0xe12fff33], end=0x1003)

    def test_rejects_unmapped_interval(self):
        with self.assertRaises(ValueError):
            self.run_trace([0xe12fff33], end=0x1008)

    def test_call_does_not_change_default_method_bounds(self):
        before = flow.START, flow.CODE_END
        self.run_trace([0xe12fff33])
        self.assertEqual((flow.START, flow.CODE_END), before)


if __name__ == '__main__':
    unittest.main()
