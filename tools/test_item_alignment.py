#!/usr/bin/env python3
"""Regression tests for generation/validation, without editing the source tree."""
import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import align_rebuild_items as align
import test_item_id_alignment_evidence as guard

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key: ' + key)
        result[key] = value
    return result


class ItemAlignmentTest(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / 'assets/gamedata/items.json').read_text()
        self.items = json.loads(self.text)
        self.table = guard.parse_table((NATIVE / 'original_item_types.tsv').read_text())

    def run_aligner(self, text):
        with tempfile.TemporaryDirectory() as folder:
            item_path, table_path = Path(folder) / 'items.json', Path(folder) / 'alignment.tsv'
            item_path.write_text(text)
            with patch.object(align, 'ITEMS_JSON', item_path), \
                 patch.object(align, 'ALIGNMENT_TSV', table_path), \
                 patch.object(align, 'ROOT', Path(folder)), \
                 contextlib.redirect_stdout(io.StringIO()):
                result = align.main()
            self.assertEqual(result, 0)
            return item_path.read_text(), table_path.read_text()

    def test_generation_idempotent(self):
        first, table1 = self.run_aligner(self.text)
        second, table2 = self.run_aligner(first)
        self.assertEqual(first, second)
        self.assertEqual(table1, table2)
        self.assertEqual(len(json.loads(first, object_pairs_hook=unique_keys)), 87)

    def test_existing_wrong_mapping_repaired(self):
        mutated = self.text.replace('"original_type": 3, "string_id": "ITEM_FLINT"',
                                    '"original_type": 999, "string_id": "ITEM_FLINT"')
        self.assertNotEqual(mutated, self.text)
        text, _ = self.run_aligner(mutated)
        items = json.loads(text, object_pairs_hook=unique_keys)
        self.assertEqual(next(x['original_type'] for x in items if x['string_id'] == 'ITEM_FLINT'), 3)

    def test_all_mappings_checked_not_only_spots(self):
        used = {x['original_type'] for x in self.items if x['original_type'] is not None}
        unused = next(i for i in self.table if i not in used)
        for original in self.items:
            with self.subTest(item=original['string_id']):
                changed = copy.deepcopy(self.items)
                row = next(x for x in changed if x['string_id'] == original['string_id'])
                row['original_type'] = unused
                self.assertTrue(guard.check_items_json(json.dumps(changed), self.table))

    def test_swapped_copper_and_tin_rejected(self):
        changed = copy.deepcopy(self.items)
        a = next(x for x in changed if x['string_id'] == 'ITEM_COPPER_ORE')
        b = next(x for x in changed if x['string_id'] == 'ITEM_TIN_ORE')
        a['original_type'], b['original_type'] = b['original_type'], a['original_type']
        self.assertTrue(guard.check_items_json(json.dumps(changed), self.table))

    def test_duplicate_keys_rejected(self):
        changed = self.text.replace('"original_type": 31,', '"original_type": 63, "original_type": 31,', 1)
        self.assertNotEqual(changed, self.text)
        self.assertTrue(guard.check_items_json(changed, self.table))

    def test_format_independent_generation(self):
        first, _ = self.run_aligner(json.dumps(self.items, indent=2))
        second, _ = self.run_aligner(json.dumps(self.items, separators=(',', ':')))
        self.assertEqual(first, second)

    def test_invalid_original_types_rejected(self):
        for invalid in (True, 21.0, "21", [], {}, -1, 65536):
            with self.subTest(value=invalid):
                changed = copy.deepcopy(self.items)
                changed[1]['original_type'] = invalid
                self.assertTrue(guard.check_items_json(json.dumps(changed), self.table))

    def test_legacy_ids_and_full_object_set_preserved(self):
        changed = copy.deepcopy(self.items)
        changed[1]['id'] = 999
        self.assertTrue(guard.check_items_json(json.dumps(changed), self.table))
        self.assertTrue(guard.check_items_json(json.dumps(self.items[:-1]), self.table))
        self.assertTrue(guard.check_items_json(json.dumps(self.items + [self.items[0]]), self.table))

    def test_tsv_mismatch_rejected_for_every_row(self):
        text = (NATIVE / 'item_id_alignment.tsv').read_text()
        lines = text.splitlines()
        for index in range(1, len(lines)):
            with self.subTest(row=index):
                altered = list(lines)
                fields = altered[index].split('\t')
                fields[3] = '999'
                altered[index] = '\t'.join(fields)
                self.assertTrue(guard.check_alignment('\n'.join(altered) + '\n', self.text, self.table))

    def test_codegen_rejects_invalid_mapping_before_writes(self):
        import process_items
        changed = copy.deepcopy(self.items)
        changed[1]['original_type'] = 22
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'items.json'
            source.write_text(json.dumps(changed))
            outputs = [Path(folder) / name for name in ('i.h', 'i.cpp', 'r.h', 'r.cpp')]
            for path in outputs:
                path.write_text('do not overwrite')
            with self.assertRaises(ValueError):
                process_items.generate_code(source, ROOT / 'assets/gamedata/recipes.json', *outputs)
            self.assertTrue(all(path.read_text() == 'do not overwrite' for path in outputs))

    def test_atlas_domains_and_versioned_names(self):
        import extract_original_item_types as source
        rows = source.build_table()
        by_id = {int(x['item_type']): x for x in rows}
        self.assertTrue(all(x['atlas_domain'] == 'TileMap:32x32' for x in rows))
        self.assertEqual(by_id[1088]['tile_row_a0'], '18')
        self.assertEqual(by_id[1024]['server171_symbol'], 'ITEM_COBBLESTONE')
        self.assertEqual(by_id[1024]['reference_name'], 'Stone')
        self.assertNotIn('atlas_a0', by_id[1024])


if __name__ == '__main__':
    unittest.main()
