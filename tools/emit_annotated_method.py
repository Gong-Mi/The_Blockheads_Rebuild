#!/usr/bin/env python3
"""Emit one bounded ObjC method listing with pool annotations.

Thin CLI over tools/listing_core.py (the engine was refactored there so
callers that emit many listings load the ELF once). Format-compatible with
the checked-in disasm_*.txt files.

Usage:
  emit_annotated_method.py "<title>" "<types>" <start-hex> <end-hex> <outname>
"""
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from listing_core import Lister  # noqa: E402


def main():
    title, types, start_s, end_s, outname = sys.argv[1:6]
    start, end = int(start_s, 16), int(end_s, 16)
    out = TOOLS.parent / 'reconstruction/reverse-v3/native' / outname
    lister = Lister()
    text = lister.emit(title, types, start, end)
    out.write_text(text)
    lister.verify(text, start, end)
    count = sum(1 for line in text.splitlines() if line.startswith('            '))
    print(f'wrote {out.name}: {count} words')
    print('coverage gate: OK')


if __name__ == '__main__':
    main()
