#!/usr/bin/env python3
"""Self-audit: no tool may recover a filename by regexing raw binary bytes.

Two real defects came from exactly that shortcut and both produced plausible
fiction instead of an error:

  * `asset_audit.py` paired APK assets with the repository by basename, so the SD
    and HD copies of the same name were compared against each other and 22 files
    were reported as dimension mismatches (they are not);
  * the audio and shader joins regexed `libApplication.so` for `[\\w]+\\.wav`, which
    matched inside the ObjC ivar `OBJC_IVAR_$_KelpPlant.waveTimer` and invented an
    asset `_KelpPlant.wav` that does not exist.

The fix is a rule, not a habit: filename evidence comes from NUL-delimited
strings (`tools/string_evidence.py`), and assets are paired by full relative
path. This linter enforces both across `tools/`.

Exit codes: 0 clean, 1 violations found (each printed with file:line).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
EXTENSION_RE = re.compile(r"\\\.(?:wav|mp4|m4a|ogg|vsh|fsh|png|jpg|jpeg|fnt|plist|json)")
RAW_READ_RE = re.compile(r"read_bytes\(\)")
REGEX_CALL_RE = re.compile(r"re\.(?:findall|finditer|search|match|fullmatch)\(")
BASENAME_RE = re.compile(r"os\.path\.basename|Path\([^)]*\)\.name\b")
# Only pairing semantics matter: a basename used in a comparison, a set or a
# dict key is how the SD and HD copies of one name get compared to each other.
PAIRING_RE = re.compile(r"==|!=|\bin\b|set\(|add\(|key|pair")
SKIP = {"lint_evidence_scan.py", "string_evidence.py", "test_lint_evidence_scan.py"}
# Text inputs (sources, listings) are not binary blobs; only raw ELF/APK bytes
# are the hazard. Files that scan text are allowed to use plain regexes.
TEXT_INPUT_HINT = re.compile(r"read_text|decode\(|splitlines\(\)")


ADD_ARG_CALL_RE = re.compile(r"add_argument\((.*?)\)\n", re.S)
CHECK_SKIP_RE = re.compile(r"if\s+\w+\s+is\s+None\s*:\s*\n\s*continue")
OUTPUT_ARG_RE = re.compile(r'\s*"--(?:tsv|json|out|output)[\w-]*"')


def vacuous_check_violations(path: Path, text: str) -> list[str]:
    """`--check` that cannot fail is worse than no check.

    Two shapes shipped here: output paths with no default (so the comparison loop
    skipped them) and an explicit `if path is None: continue` inside the check
    block. Both let a stale artifact print "check ok" without being read.
    """
    out: list[str] = []
    if "args.check" not in text and '"--check"' not in text:
        return out
    # Only the check block counts: `if value is None: continue` is a perfectly
    # normal guard inside a decoder and must not be mistaken for a vacuous check
    # (an earlier revision of this rule flagged exactly that in
    # extract_tile_shared_body.py).
    marker = "args.check:"
    check_block = text[text.rfind(marker):] if marker in text else ""
    if CHECK_SKIP_RE.search(check_block):
        out.append(f"{path.name}: --check skips a missing/None output path "
                   f"(a stale artifact would report 'check ok')")
    for call in ADD_ARG_CALL_RE.findall(text):
        if OUTPUT_ARG_RE.match(call) and "default=" not in call and "required=True" not in call:
            out.append(f"{path.name}: output argument without a default: "
                       f"{' '.join(call.split())[:70]}")
    return out


def scan(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    violations: list[str] = []
    uses_nul_strings = "nul_strings" in text
    # File-level rule: a tool that reads raw binary and calls a regex anywhere,
    # without ever going through NUL-string extraction, is one accidental
    # suffix away from inventing a filename. Flag every regex line in it.
    binary_and_regex = (
        RAW_READ_RE.search(text) is not None
        and REGEX_CALL_RE.search(text) is not None
        and not uses_nul_strings
        and TEXT_INPUT_HINT.search(text) is None
    )
    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("#"):
            continue
        if EXTENSION_RE.search(line) and REGEX_CALL_RE.search(line) and not uses_nul_strings:
            violations.append(
                f"{path.name}:{number}: extension regex without NUL-string "
                f"extraction (use tools/string_evidence.py): {line.strip()[:90]}"
            )
        if (BASENAME_RE.search(line) and PAIRING_RE.search(line)
                and "assets" in text.lower() and "sha256" in text):
            violations.append(
                f"{path.name}:{number}: basename pairing in an asset audit - pair by "
                f"full relative path instead: {line.strip()[:90]}"
            )
        if RAW_READ_RE.search(line) and REGEX_CALL_RE.search(line) and not TEXT_INPUT_HINT.search(text):
            violations.append(
                f"{path.name}:{number}: regex applied to raw bytes: {line.strip()[:90]}"
            )
        elif binary_and_regex and REGEX_CALL_RE.search(line) and "read_text" not in line:
            violations.append(
                f"{path.name}:{number}: regex in a raw-byte reader with no NUL-string "
                f"extraction: {line.strip()[:90]}"
            )
    violations.extend(vacuous_check_violations(path, text))
    return violations


def main() -> int:
    checked = 0
    violations: list[str] = []
    for path in sorted(TOOLS.glob("*.py")):
        if path.name in SKIP or path.name.startswith("test_"):
            continue
        checked += 1
        violations.extend(scan(path))
    for item in violations:
        print(item, file=sys.stderr)
    print(f"evidence-scan lint: {checked} tools checked, {len(violations)} violations")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
