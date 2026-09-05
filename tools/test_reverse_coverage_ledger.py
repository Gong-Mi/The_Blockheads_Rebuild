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
