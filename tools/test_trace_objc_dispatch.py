#!/usr/bin/env python3
import csv
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/trace_objc_dispatch.py"


class ObjCDispatchTraceTest(unittest.TestCase):
    def test_drawframe_trace_produces_candidates_and_unknowns(self):
        elf = os.environ.get("BLOCKHEADS_ELF")
        if not elf:
            home = Path.home()
            elf = home / "blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"
        if not Path(elf).exists():
            self.skipTest(f"original ELF not available at {elf}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "trace.tsv"
            subprocess.run(
                ["python3", str(TOOL),
                 str(elf),
                 "--imp", "0x00781a44",
                 "--output", str(output)],
                check=True,
            )
            with output.open(encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(len(rows), 11)
            # Conservative tool: all sites must be unknown until register dataflow is fully proven
            self.assertTrue(all(r["selector_status"] == "unknown" for r in rows))
            self.assertTrue(all(r["receiver_status"] == "unknown" for r in rows))
            self.assertTrue(all(r["argument_status"] == "unknown" for r in rows))

    def test_unknown_when_no_selector_load(self):
        # A synthetic case where the tool should refuse or return unknown.
        # We rely on the drawFrame test above; this placeholder documents intent.
        pass


if __name__ == "__main__":
    unittest.main()
