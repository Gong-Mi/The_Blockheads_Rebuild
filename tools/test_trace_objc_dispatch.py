#!/usr/bin/env python3
"""Dependency-free dataflow regressions plus optional real-ELF acceptance."""
import os
from pathlib import Path
import unittest
import trace_objc_dispatch as trace


class Memory:
    def __init__(self):
        self.words = {0x100: 0x200, 0x104: 0x300}
        self.selectors = {0x200: 'removeFromSuperview'}
        self.imports = {0x104: 'objc_msgSend'}

    def word(self, address):
        return self.words.get(address)


def analyze(*instructions):
    ops = [{'addr': 0x1000 + i * 4, 'disasm': text}
           for i, text in enumerate(instructions)]
    return trace.analyze_ops(ops, Memory())


class DispatchDataflowTest(unittest.TestCase):
    def test_selector_is_r1_not_call_target(self):
        row, = analyze('ldr r3, [0x104]', 'ldr r1, [0x100]', 'blx r3')
        self.assertEqual(row['target_symbol'], 'objc_msgSend')
        self.assertEqual(row['selector_name'], 'removeFromSuperview')
        self.assertEqual(row['selector_status'], 'candidate')

    def test_unrecognized_write_invalidates_register(self):
        row, = analyze('ldr r3, [0x104]', 'ldr r1, [0x100]',
                       'eor r1, r1, r1', 'blx r3')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_call_clobbers_argument_registers(self):
        rows = analyze('ldr r4, [0x104]', 'ldr r1, [0x100]', 'blx r4', 'blx r4')
        self.assertEqual(rows[0]['selector_status'], 'candidate')
        self.assertEqual(rows[1]['selector_status'], 'unknown')

    def test_branch_barrier_does_not_merge_linear_paths(self):
        row, = analyze('ldr r3, [0x104]', 'ldr r1, [0x100]', 'beq 0x1010',
                       'movw r1, 0', 'blx r3')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_conditional_write_invalidates_register(self):
        row, = analyze('ldr r3, [0x104]', 'ldr r1, [0x100]', 'moveq r1, r2', 'blx r3')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_unknown_target_not_labelled_objc_dispatch(self):
        row, = analyze('ldr r1, [0x100]', 'blx r3')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_pic_arithmetic_and_register_alias(self):
        # ARM pc is instruction address + 8, not the literal-load address.
        memory = Memory()
        memory.words[0x108] = (0x100 - (0x1004 + 8)) & 0xffffffff
        ops = [{'addr': 0x1000 + i * 4, 'disasm': text} for i, text in enumerate([
            'ldr r2, [0x108]', 'add r2, pc, r2', 'ldr r1, [r2]',
            'ldr ip, [0x104]', 'blx r12'])]
        row, = trace.analyze_ops(ops, memory)
        self.assertEqual(row['selector_name'], 'removeFromSuperview')

    def test_backedge_removes_stale_selector(self):
        row, = analyze('ldr r4, [0x104]', 'ldr r1, [0x100]',
                       'blx r4', 'bne 0x1008')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_writeback_invalidates_base(self):
        row, = analyze('ldr r3, [0x104]', 'ldr r1, [0x100]',
                       'ldr r2, [r1], 4', 'blx r3')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_byte_store_preserves_unmodified_registers(self):
        row, = analyze('ldr r3, [0x104]', 'ldr r1, [0x100]',
                       'strb r0, [r2]', 'blx r3')
        self.assertEqual(row['selector_name'], 'removeFromSuperview')

    def test_partial_stack_store_invalidates_saved_word(self):
        row, = analyze('ldr r3, [0x104]', 'ldr r1, [0x100]',
                       'str r1, [fp, -0x20]', 'strb r0, [fp, -0x1f]',
                       'ldr r1, [fp, -0x20]', 'blx r3')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_background_store_rejects_changed_instructions(self):
        from unittest.mock import patch
        import recover_drawframe_background_store as recovery
        memory = Memory()
        with patch.object(recovery, 'ELFMemory', return_value=memory):
            with self.assertRaisesRegex(ValueError, 'ARM instruction mismatch'):
                recovery.recover(Path('unused-by-fixture'))

    def test_overlapping_word_store_invalidates_saved_selector(self):
        row, = analyze('ldr r3, [0x104]', 'ldr r1, [0x100]',
                       'str r1, [fp, -0x20]', 'str r0, [fp, -0x1f]',
                       'ldr r1, [fp, -0x20]', 'blx r3')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_other_frame_base_may_alias_saved_selector(self):
        row, = analyze('ldr r3, [0x104]', 'ldr r1, [0x100]',
                       'str r1, [fp, -0x20]', 'str r0, [sp, 0]',
                       'ldr r1, [fp, -0x20]', 'blx r3')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_prologue_fp_sp_same_slot(self):
        row, = analyze('push {fp, lr}', 'mov fp, sp', 'sub sp, sp, 0x20',
                       'ldr r3, [0x104]', 'ldr r1, [0x100]',
                       'str r1, [fp, -0x10]', 'ldr r1, [sp, 0x10]', 'blx r3')
        self.assertEqual(row['selector_status'], 'candidate')

    def test_proven_cross_base_nonoverlap(self):
        row, = analyze('mov fp, sp', 'sub sp, sp, 0x40',
                       'ldr r3, [0x104]', 'ldr r1, [0x100]',
                       'str r1, [fp, -0x10]', 'str r0, [sp, 0]',
                       'ldr r1, [fp, -0x10]', 'blx r3')
        self.assertEqual(row['selector_status'], 'candidate')

    def test_proven_cross_base_overlap(self):
        row, = analyze('mov fp, sp', 'sub sp, sp, 0x10',
                       'ldr r3, [0x104]', 'ldr r1, [0x100]',
                       'str r1, [fp, -0x10]', 'str r0, [sp]',
                       'ldr r1, [fp, -0x10]', 'blx r3')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_stack_adjustment_backedge_loses_nonconstant_base(self):
        row, = analyze('ldr r4, [0x104]', 'ldr r1, [0x100]',
                       'str r1, [sp]', 'sub sp, sp, 4', 'bne 0x100c',
                       'ldr r1, [sp, 4]', 'blx r4')
        self.assertEqual(row['selector_status'], 'unknown')

    def test_push_preserves_register_order_and_frame_coordinates(self):
        row, = analyze('ldr r4, [0x100]', 'ldr r5, [0x104]',
                       'push {r5, r4}', 'ldr r1, [sp]', 'blx r5')
        self.assertEqual(row['selector_status'], 'candidate')

    def test_escaped_stack_address_invalidates_slots_across_call(self):
        row, = analyze('ldr r4, [0x104]', 'ldr r1, [0x100]',
                       'str r1, [sp]', 'mov r0, sp', 'blx r4',
                       'ldr r1, [sp]', 'blx r4')[-1:]
        self.assertEqual(row['selector_status'], 'unknown')

    def test_stack_roundtrip(self):
        row, = analyze('ldr r3, [0x104]', 'ldr r1, [0x100]',
                       'str r1, [fp, -0x20]', 'movw r1, 0',
                       'ldr r1, [fp, -0x20]', 'blx r3')
        self.assertEqual(row['selector_name'], 'removeFromSuperview')


class OriginalELFTest(unittest.TestCase):
    def test_drawframe_first_dispatch(self):
        elf = os.environ.get('BLOCKHEADS_ELF')
        if not elf:
            self.skipTest('set BLOCKHEADS_ELF for original binary acceptance')
        rows = trace.analyze(Path(elf), 0x00781a44)
        self.assertEqual(len(rows), 11)
        first = next(r for r in rows if r['call_address'] == '0x00781b28')
        self.assertEqual(first['selector_name'], 'removeFromSuperview')
        self.assertEqual(first['target_symbol'], 'objc_msgSend')
        self.assertTrue(all(r['receiver_status'] == r['argument_status'] == 'unknown' for r in rows))


if __name__ == '__main__':
    unittest.main()
