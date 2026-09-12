#!/usr/bin/env python3
import csv
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/build_reverse_coverage_ledger.py"


class CoverageLedgerTest(unittest.TestCase):
    def test_stages_are_conservative_and_address_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            methods = root / "methods.tsv"
            with methods.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
                writer.writerow(["implementation", "class", "kind", "selector", "types"])
                writer.writerow(["0x00000010", "World", "instance", "saveAll", "v@:"])
                writer.writerow(["0x00000020", "World", "instance", "loadGame", "v@:"])
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "refs_world_lifecycle.tsv").write_text(
                "implementation\n0x00000010\n", encoding="utf-8"
            )
            (evidence / "CONTENT_CONTROL_FLOW_STATS.md").write_text(
                "IMP: `0x00000020`\n", encoding="utf-8"
            )
            output = root / "ledger.json"
            report = root / "ledger.md"
            subprocess.run(
                ["python3", str(TOOL), str(methods), "--evidence-root", str(evidence),
                 "--json", str(output), "--markdown", str(report)],
                check=True,
            )
            ledger = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(ledger["stage_counts"], {
                "indexed": 2, "refs": 1, "cfg": 1,
                "semantics": 0, "implemented": 0, "behavior-verified": 0,
            })
            self.assertEqual(ledger["entries"][0]["semantic_status"], "unknown")
            self.assertFalse(ledger["entries"][1]["stages"]["refs"])

    def test_evidence_owners_exclude_boundaries_callees_and_values(self):
        from build_reverse_coverage_ledger import implementations_in_files
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disasm = root / 'disasm_sample.txt'
            disasm.write_text('# implementation: 0x00000010\n'
                              '# ARM.exidx end: 0x00000020\n'
                              '0x00000014 bl 0x00000030\n')
            refs = root / 'refs_sample.tsv'
            refs.write_text('implementation\treference_address\tvalue\n'
                            '0x00000040\t0x00000050\t0x00000060\n')
            found_refs, found_cfg = implementations_in_files([disasm, refs])
            self.assertEqual(found_refs, {'0x00000010', '0x00000040'})
            self.assertEqual(found_cfg, {'0x00000010'})

    def test_explicit_method_record_does_not_claim_original_runtime(self):
        from build_reverse_coverage_ledger import build
        row={'implementation':'0x00000010','class':'View','kind':'instance','selector':'update','types':'v@:'}
        record={**row,'source':'view.cpp','test':'test_view.cpp','evidence':'view.md',
                'scope':'typed method only','integration':'recovered-method-module'}
        result=build([row],set(),set(),{row['implementation']:record})
        self.assertEqual(result['stage_counts']['implemented'],1)
        self.assertEqual(result['stage_counts']['semantics'],1)
        self.assertEqual(result['stage_counts']['behavior-verified'],0)
        self.assertEqual(result['entries'][0]['implementation_record']['scope'],'typed method only')

    def test_record_identity_and_file_validation(self):
        from build_reverse_coverage_ledger import build, read_implementation_records
        row={'implementation':'0x00000010','class':'View','kind':'instance','selector':'update','types':'v@:'}
        record={**row,'source':'view.cpp','test':'test.cpp','evidence':'proof.md',
                'scope':'typed method','integration':'recovered-method-module'}
        for bad in ({**record,'selector':'other'}, {**record,'implementation':'0x00000020'}):
            with self.assertRaisesRegex(ValueError,'identity mismatch'):
                build([row],set(),set(),{bad['implementation']:bad})
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('view.cpp','test.cpp','proof.md'):
                (root/name).write_text('fixture')
            manifest=root/'records.json'
            manifest.write_text(json.dumps({'schema':1,'methods':[record]}))
            self.assertEqual(len(read_implementation_records(manifest,root)),1)
            for bad in ({**record,'source':'missing.cpp'}, {**record,'source':'../outside.cpp'},
                        {**record,'implementation':'0x10'}, {**record,'scope':''}):
                manifest.write_text(json.dumps({'schema':1,'methods':[bad]}))
                with self.assertRaises(ValueError): read_implementation_records(manifest,root)
            manifest.write_text(json.dumps({'schema':1,'methods':[record,record]}))
            with self.assertRaisesRegex(ValueError,'duplicate'):
                read_implementation_records(manifest,root)

    def test_duplicate_imp_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            methods = root / "methods.tsv"
            methods.write_text(
                "implementation\tclass\tkind\tselector\ttypes\n"
                "0x10\tA\tinstance\ta\tv@:\n"
                "0x10\tB\tinstance\tb\tv@:\n", encoding="utf-8"
            )
            evidence = root / "evidence"
            evidence.mkdir()
            result = subprocess.run(
                ["python3", str(TOOL), str(methods), "--evidence-root", str(evidence),
                 "--json", str(root / "out.json"), "--markdown", str(root / "out.md")],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate implementation", result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
