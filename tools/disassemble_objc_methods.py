#!/usr/bin/env python3
"""Disassemble selected Objective-C methods using ELF metadata and ARM unwind bounds."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

from extract_objc_methods import Elf32ObjCReader, Method


def unwind_function_starts(elf: Path) -> list[int]:
    output = subprocess.check_output(
        ["llvm-readelf", "--unwind", str(elf)], text=True, errors="replace"
    )
    starts = {
        int(match.group(1), 16)
        for match in re.finditer(r"FunctionAddress:\s*0x([0-9A-Fa-f]+)", output)
    }
    return sorted(starts)


def function_end(start: int, starts: list[int], file_size: int) -> int:
    for candidate in starts:
        if candidate > start:
            return candidate
    return file_size


def disassemble(elf: Path, method: Method, end: int) -> str:
    byte_count = end - method.implementation
    command = [
        "r2",
        "-q",
        "-e",
        "scr.color=false",
        "-e",
        "bin.relocs.apply=true",
        "-c",
        f"pD {byte_count} @ 0x{method.implementation:x}; q",
        str(elf),
    ]
    assembly = subprocess.check_output(command, text=True, errors="replace")
    header = (
        f"# {method.class_name} {'+' if method.kind == 'class' else '-'}"
        f"[{method.selector}]\n"
        f"# types: {method.types}\n"
        f"# implementation: 0x{method.implementation:08x}\n"
        f"# ARM.exidx end: 0x{end:08x}\n\n"
    )
    return header + assembly.rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--class", dest="class_pattern", required=True)
    parser.add_argument("--selector", dest="selector_pattern", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    class_pattern = re.compile(args.class_pattern)
    selector_pattern = re.compile(args.selector_pattern)
    reader = Elf32ObjCReader(args.elf)
    methods = [
        method
        for method in reader.all_methods(warn=False)
        if class_pattern.search(method.class_name) and selector_pattern.search(method.selector)
    ]
    if not methods:
        raise SystemExit("no matching Objective-C methods")

    starts = unwind_function_starts(args.elf)
    chunks = [
        disassemble(
            args.elf,
            method,
            function_end(method.implementation, starts, len(reader.data)),
        )
        for method in methods
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n\n".join(chunks), encoding="utf-8")
    print(f"wrote {len(methods)} methods to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
