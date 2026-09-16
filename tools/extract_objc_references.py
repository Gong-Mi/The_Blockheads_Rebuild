#!/usr/bin/env python3
"""Resolve selector and constant-string references used by Objective-C methods.

Apportable ARMv7 code addresses Objective-C metadata relative to a per-function
PIC base. This tool recognizes the generated ldr/add sequence, resolves section
references, and emits the selectors and CFStrings used by each selected method.
"""

from __future__ import annotations

import argparse
import re
import struct
import subprocess
from pathlib import Path

from disassemble_objc_methods import function_end, unwind_function_starts
from extract_objc_methods import Elf32ObjCReader, Method


LITERAL_RE = re.compile(r"\[0x[0-9a-f]+:4\]=0x([0-9a-f]+)")
BASE_LOAD_RE = re.compile(
    r"0x([0-9a-f]+).*?ldr (\w+), \[0x[0-9a-f]+\].*?=0x([0-9a-f]+)"
)


def signed32(value: int) -> int:
    return value - (1 << 32) if value & 0x80000000 else value


def section_range(elf: Path, marker: str) -> tuple[int, int]:
    output = subprocess.check_output(
        ["llvm-readelf", "-S", "--wide", str(elf)], text=True, errors="replace"
    )
    for line in output.splitlines():
        if marker not in line:
            continue
        match = re.search(
            r"PROGBITS\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)",
            line,
        )
        if match:
            start = int(match.group(1), 16)
            return start, start + int(match.group(2), 16)
    raise ValueError(f"section containing {marker!r} was not found")


def r2_disassembly(elf: Path, start: int, end: int) -> str:
    return subprocess.check_output(
        [
            "r2",
            "-q",
            "-e",
            "scr.color=false",
            "-e",
            "bin.relocs.apply=true",
            "-c",
            f"pD {end - start} @ 0x{start:x}; q",
            str(elf),
        ],
        text=True,
        errors="replace",
        stderr=subprocess.DEVNULL,
    )


def pic_base(disassembly: str) -> int:
    lines = disassembly.splitlines()
    for index, line in enumerate(lines[:-1]):
        load = BASE_LOAD_RE.search(line)
        if not load:
            continue
        register = load.group(2)
        add = re.search(
            rf"0x([0-9a-f]+).*?add {re.escape(register)}, pc, {re.escape(register)}",
            lines[index + 1],
        )
        if add:
            return int(add.group(1), 16) + 8 + signed32(int(load.group(3), 16))
    raise ValueError("PIC base sequence not found")


def cstring(data: bytes, address: int) -> str:
    if address <= 0 or address >= len(data):
        return f"<invalid:0x{address:x}>"
    end = data.find(b"\0", address)
    if end < 0:
        return f"<unterminated:0x{address:x}>"
    return data[address:end].decode("utf-8", "replace")


def references_for_method(
    elf: Path,
    data: bytes,
    method: Method,
    end: int,
    selector_range: tuple[int, int],
    cfstring_range: tuple[int, int],
) -> list[tuple[str, int, str]]:
    disassembly = r2_disassembly(elf, method.implementation, end)
    base = pic_base(disassembly)
    references: set[tuple[str, int, str]] = set()
    for raw_value in LITERAL_RE.findall(disassembly):
        target = base + signed32(int(raw_value, 16))
        if selector_range[0] <= target < selector_range[1]:
            pointer = struct.unpack_from("<I", data, target)[0]
            references.add(("selector", target, cstring(data, pointer)))
        elif cfstring_range[0] <= target < cfstring_range[1]:
            pointer = struct.unpack_from("<I", data, target + 8)[0]
            references.add(("cfstring", target, cstring(data, pointer)))
    return sorted(references, key=lambda item: (item[0], item[1], item[2]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--class", dest="class_pattern", required=True)
    parser.add_argument("--selector", dest="selector_pattern", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    reader = Elf32ObjCReader(args.elf)
    class_pattern = re.compile(args.class_pattern)
    selector_pattern = re.compile(args.selector_pattern)
    methods = [
        method
        for method in reader.all_methods(warn=False)
        if class_pattern.search(method.class_name) and selector_pattern.search(method.selector)
    ]
    if not methods:
        raise SystemExit("no matching Objective-C methods")

    starts = unwind_function_starts(args.elf)
    selector_range = section_range(args.elf, "__objc_selrefs")
    cfstring_range = section_range(args.elf, "__cfstring")
    rows: list[str] = ["implementation\tclass\tmethod\treference_kind\treference_address\tvalue"]
    for method in methods:
        end = function_end(method.implementation, starts, len(reader.data))
        for kind, address, value in references_for_method(
            args.elf, reader.data, method, end, selector_range, cfstring_range
        ):
            escaped = value.replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")
            rows.append(
                f"0x{method.implementation:08x}\t{method.class_name}\t{method.selector}"
                f"\t{kind}\t0x{address:08x}\t{escaped}"
            )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"wrote {len(rows) - 1} references from {len(methods)} methods to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
