#!/usr/bin/env python3
import csv
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/index_arm_indirect_calls.py"


class IndirectCallIndexTest(unittest.TestCase):
    def test_indexes_blx_and_keeps_dispatch_unknown(self):
        text = """
            0x00001000      e3a00000       mov r0, 0
            0x00001004      33ff2fe1       blx r3
            0x00001008      12ff2fe1       blx r2
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disasm = root / "sample.txt"
            output = root / "calls.tsv"
            disasm.write_text(text, encoding="utf-8")
            subprocess.run(["python3", str(TOOL), str(disasm), "--output", str(output)], check=True)
            with output.open(encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual([row["call_address"] for row in rows], ["0x00001004", "0x00001008"])
            self.assertEqual({row["selector_pair"] for row in rows}, {"unknown"})
            self.assertEqual([row["target_register"] for row in rows], ["r3", "r2"])

    def test_fails_without_indirect_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disasm = root / "sample.txt"
            disasm.write_text("0x1000 deadbeef nop\n", encoding="utf-8")
            result = subprocess.run(["python3", str(TOOL), str(disasm), "--output", str(root / "calls.tsv")], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no ARM blx", result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
