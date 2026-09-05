"""Synthetic merge checks plus hash-pinned original-DWARF round-trip tests.
Run: python -B tools/test_server_types.py --elf ~/blockheads-work/server/blockheads_server171
"""
import argparse
import copy
import json
from pathlib import Path
import unittest

import recover_server_types as recovery

ELF = None
ARTIFACT = Path(__file__).resolve().parents[1] / 'reconstruction/reverse-v3/native/server_types.json'


class MergeTests(unittest.TestCase):
    def test_identical_definitions_merge_provenance(self):
        merged = recovery.merge_definitions('E', [({'bytes': 4, 'values': [{'name': 'a', 'value': -1}, {'name': 'alias', 'value': -1}]}, {'die_offset': 1}), ({'bytes': 4, 'values': [{'name': 'a', 'value': -1}, {'name': 'alias', 'value': -1}]}, {'die_offset': 2})])
        self.assertEqual(len(merged['sources']), 2)
        self.assertEqual(len(merged['values']), 2)

    def test_conflicting_values_size_members_and_type_rejected(self):
        base = {'bytes': 4, 'members': [{'name': 'x', 'offset': 0, 'type': {'name': 'int'}}], 'values': [{'name': 'a', 'value': 1}]}
        alternatives = []
        for field, value in [('bytes', 8), ('members', []), ('values', [{'name': 'a', 'value': 2}])]:
            changed = copy.deepcopy(base)
            changed[field] = value
            alternatives.append(changed)
        for field, value in [('offset', 1), ('type', {'name': 'unsigned int'}), ('name', 'y')]:
            changed = copy.deepcopy(base)
            changed['members'][0][field] = value
            alternatives.append(changed)
        for changed in alternatives:
            with self.subTest(changed=changed), self.assertRaises(recovery.DefinitionConflict):
                recovery.merge_definitions('E', [(base, {'die_offset': 1}), (changed, {'die_offset': 2})])

    def test_missing_type_is_not_invented(self):
        self.assertIsNone(recovery.type_description(None))

    def test_wrong_hash_rejected_before_elf_parse(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            recovery.recover(Path(__file__))


class OriginalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if ELF is None:
            raise unittest.SkipTest('pass --elf for original ELF acceptance')
        cls.result = recovery.recover(ELF)

    def test_artifact_exact_regeneration(self):
        self.assertEqual(self.result, json.loads(ARTIFACT.read_text()))

    def test_structures_complete(self):
        for name, size, count in [('Tile', 64, 26), ('PhysicalBlock', 328, 10)]:
            with self.subTest(name=name):
                record = self.result['structures'][name]
                self.assertEqual(record['bytes'], size)
                self.assertEqual(len(record['members']), count)
                self.assertGreater(len(record['sources']), 1)
                for member in record['members']:
                    self.assertIsInstance(member['offset'], int)
                    self.assertIsNotNone(member['type'])
        physical = {m['name']: m for m in self.result['structures']['PhysicalBlock']['members']}
        self.assertEqual(physical['clientExplored']['offset'], 296)
        self.assertEqual(physical['clientLightBlocks']['type']['subranges'][0]['count'], 32)
        tile = {m['name']: m for m in self.result['structures']['Tile']['members']}
        self.assertEqual(tile['padding']['offset'], 48)
        self.assertEqual(tile['padding']['type']['subranges'][0]['count'], 8)
        self.assertEqual(tile['artificialHeat']['type']['target']['encoding'], 5)
        self.assertEqual(tile['typeIndex']['type']['name'], 'uint8_t')

    def test_enum_counts_and_dedup(self):
        for name, count, copies in [('TileType', 78, 50), ('ItemType', 428, 85)]:
            record = self.result['enums'][name]
            self.assertEqual(len(record['values']), count)
            self.assertEqual(len(record['sources']), copies)
            self.assertEqual(record['bytes'], 4)
            self.assertEqual(len({v['name'] for v in record['values']}), count)
            self.assertTrue(all(isinstance(v['value'], int) for v in record['values']))
        self.assertIn('TileContents', self.result['enums'])
        self.assertEqual(self.result['conflicts'], [])

    def test_every_original_definition_independent_projection(self):
        # Independent direct-DIE oracle: verifies ALL member rows and enum values,
        # not merely golden counts or agreement between extractor and itself.
        from elftools.elf.elffile import ELFFile
        with ELF.open('rb') as stream:
            dwarf = ELFFile(stream).get_dwarf_info()
            definitions = 0
            for cu in dwarf.iter_CUs():
                for die in cu.iter_DIEs():
                    attr = die.attributes.get('DW_AT_name')
                    name = attr.value.decode() if attr else None
                    if die.attributes.get('DW_AT_declaration'):
                        continue
                    if die.tag == 'DW_TAG_enumeration_type' and name:
                        expected = [(c.attributes['DW_AT_name'].value.decode(), c.attributes['DW_AT_const_value'].value) for c in die.iter_children() if c.tag == 'DW_TAG_enumerator']
                        actual = [(v['name'], v['value']) for v in self.result['enums'][name]['values']]
                    elif die.tag == 'DW_TAG_structure_type' and name in ('Tile', 'PhysicalBlock'):
                        expected = [(c.attributes['DW_AT_name'].value.decode(), c.attributes['DW_AT_data_member_location'].value) for c in die.iter_children() if c.tag == 'DW_TAG_member']
                        actual = [(m['name'], m['offset']) for m in self.result['structures'][name]['members']]
                    else:
                        continue
                    self.assertEqual(actual, expected, (name, hex(die.offset)))
                    definitions += 1
            self.assertEqual(definitions, self.result['counts']['definitions_merged'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--elf', type=Path)
    args, rest = parser.parse_known_args()
    ELF = args.elf.expanduser().resolve() if args.elf else None
    unittest.main(argv=[__file__] + rest)
