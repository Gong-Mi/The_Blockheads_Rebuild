#!/usr/bin/env python3
"""Contract test for the evidence-scan linter (runs in CI, needs no binary).

The linter exists because two shipped audits produced fiction from a raw-byte
regex (a phantom `_KelpPlant.wav`) and from basename pairing (22 phantom
dimension mismatches). This test keeps it honest in both directions: the real
tools/ tree must be clean, and a synthetic offender must still be caught.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINTER = ROOT / "tools/lint_evidence_scan.py"

BAD_SAMPLE = '''import re
from pathlib import Path


def bogus(elf: Path):
    blob = elf.read_bytes()
    return set(re.findall(r"[A-Za-z0-9_]+\\.wav", blob))
'''

# Two more shapes that shipped in this repository and looked verified: a check
# that skips its own comparison, and an output path with no canonical default.
VACUOUS_CHECK_SAMPLE = '''import argparse
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", type=Path)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.check:
        for path, expected in ((args.tsv, "x"),):
            if path is None:
                continue
            if path.read_text() != expected:
                return 1
    return 0
'''


def main() -> int:
    ok = subprocess.run([sys.executable, str(LINTER)], capture_output=True, text=True)
    assert ok.returncode == 0, f"tools/ is not clean:\n{ok.stdout}\n{ok.stderr}"
    assert "0 violations" in ok.stdout, ok.stdout

    sys.path.insert(0, str(ROOT / "tools"))
    import lint_evidence_scan as lint  # noqa: E402

    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "bogus_tool.py"
        sample.write_text(BAD_SAMPLE, encoding="utf-8")
        found = lint.scan(sample)
    assert found, "the synthetic raw-byte regex offender was not flagged"
    assert any("NUL-string" in item or "raw bytes" in item for item in found), found

    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "vacuous_check_tool.py"
        sample.write_text(VACUOUS_CHECK_SAMPLE, encoding="utf-8")
        vacuous = lint.scan(sample)
    assert any("skips a missing/None output path" in item for item in vacuous), vacuous
    assert any("output argument without a default" in item for item in vacuous), vacuous

    # Negative control: the same None-guard inside a decoder (not the check block)
    # must not be reported, or every tool with a decoder trips the rule.
    decoder_sample = '''import argparse
from pathlib import Path


def decode(word):
    value = None if word == 0 else word
    if value is None:
        continue
    return value


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", type=Path, default=Path("out.tsv"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.check:
        if not args.tsv.exists():
            return 1
    return 0
'''
    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "decoder_with_guard.py"
        sample.write_text(decoder_sample, encoding="utf-8")
        clean = lint.scan(sample)
    assert not any("skips a missing/None output path" in item for item in clean), clean

    # Third control: two views fed from different sources must be flagged.
    split_view_sample = '''def extract_rows(elf):
    return [{"a": 1}]


def render(elf):
    return "\\n".join(str(r) for r in extract_rows(elf))


def build_record(elf, sha):
    return {"rows": extract_rows(elf)}
'''
    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "split_view_tool.py"
        sample.write_text(split_view_sample, encoding="utf-8")
        split = lint.scan(sample)
    assert any("can diverge" in item for item in split), split

    # ... and the single-source pattern must not be flagged.
    single_source_sample = '''def extract_rows(elf):
    return [{"a": 1}]


def build_record(elf, sha):
    rows = extract_rows(elf)
    return {"rows": rows}


def render(elf):
    return "\\n".join(str(r) for r in build_record(elf, "")["rows"])
'''
    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "single_source_tool.py"
        sample.write_text(single_source_sample, encoding="utf-8")
        clean2 = lint.scan(sample)
    assert not any("can diverge" in item for item in clean2), clean2

    print("evidence-scan lint: PASS (clean tree + synthetic offenders flagged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
