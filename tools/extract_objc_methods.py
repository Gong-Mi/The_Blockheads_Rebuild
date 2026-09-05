#!/usr/bin/env python3
"""Extract Objective-C 2 class, ivar, and method metadata from a 32-bit ELF.

The Blockheads Android binary is an Apportable Objective-C++ ELF. Its class
metadata is directly usable even though the executable is stripped. This tool
turns the metadata into a stable, address-bearing method map that can seed
static disassembly without requiring a GUI decompiler.
"""

from __future__ import annotations

import argparse
import csv
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Method:
    class_name: str
    kind: str
    selector: str
    types: str
    implementation: int


class Elf32ObjCReader:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        if self.data[:5] != b"\x7fELF\x01":
            raise ValueError("expected a 32-bit ELF")
        if self.data[5] != 1:
            raise ValueError("only little-endian ELF is supported")
        self.symbols = self._read_symbols()

    def u32(self, address: int) -> int:
        if address < 0 or address + 4 > len(self.data):
            raise ValueError(f"address outside file-backed image: 0x{address:x}")
        return struct.unpack_from("<I", self.data, address)[0]

    def cstring(self, address: int) -> str:
        if address <= 0 or address >= len(self.data):
            return f"<invalid:0x{address:x}>"
        end = self.data.find(b"\0", address)
        if end < 0:
            return f"<unterminated:0x{address:x}>"
        return self.data[address:end].decode("utf-8", "replace")

    def _read_symbols(self) -> dict[str, int]:
        output = subprocess.check_output(
            ["llvm-readelf", "-Ws", str(self.path)],
            text=True,
            errors="replace",
        )
        pattern = re.compile(
            r"^\s*\d+:\s+([0-9a-fA-F]+).*?\s"
            r"(OBJC_(?:META)?CLASS_\$_\S+)\s*$",
            re.MULTILINE,
        )
        return {match.group(2): int(match.group(1), 16) for match in pattern.finditer(output)}

    def methods_for_class_object(self, symbol: str, kind: str) -> list[Method]:
        class_address = self.symbols[symbol]
        # objc_class: isa, superclass, cache, vtable, data. Low data bits are flags.
        class_ro = self.u32(class_address + 16) & ~3
        class_name = self.cstring(self.u32(class_ro + 16))
        method_list = self.u32(class_ro + 20)
        if method_list == 0:
            return []

        entry_size = self.u32(method_list) & 0xFFFF
        count = self.u32(method_list + 4)
        if entry_size < 12 or entry_size > 256 or count > 10000:
            raise ValueError(
                f"invalid method list for {class_name}: entry={entry_size}, count={count}"
            )

        result: list[Method] = []
        for index in range(count):
            entry = method_list + 8 + index * entry_size
            result.append(
                Method(
                    class_name=class_name,
                    kind=kind,
                    selector=self.cstring(self.u32(entry)),
                    types=self.cstring(self.u32(entry + 4)),
                    implementation=self.u32(entry + 8),
                )
            )
        return result

    def all_methods(self, strict: bool = False, warn: bool = True) -> list[Method]:
        methods: list[Method] = []
        for symbol in sorted(self.symbols):
            try:
                if symbol.startswith("OBJC_CLASS_$_"):
                    methods.extend(self.methods_for_class_object(symbol, "instance"))
                elif symbol.startswith("OBJC_METACLASS_$_"):
                    methods.extend(self.methods_for_class_object(symbol, "class"))
            except ValueError as error:
                # A few imported/runtime symbols are not file-backed class objects.
                # They are not evidence about the application's own method lists.
                if strict:
                    raise
                if warn:
                    print(f"warning: skipping {symbol}: {error}", file=sys.stderr)
        return sorted(
            set(methods),
            key=lambda method: (method.implementation, method.class_name, method.kind, method.selector),
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--class", dest="class_pattern", help="regular expression for class names")
    parser.add_argument("--selector", dest="selector_pattern", help="regular expression for selectors")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    reader = Elf32ObjCReader(args.elf)
    methods = reader.all_methods()
    if args.class_pattern:
        pattern = re.compile(args.class_pattern, re.IGNORECASE)
        methods = [method for method in methods if pattern.search(method.class_name)]
    if args.selector_pattern:
        pattern = re.compile(args.selector_pattern, re.IGNORECASE)
        methods = [method for method in methods if pattern.search(method.selector)]

    stream = args.output.open("w", encoding="utf-8", newline="") if args.output else sys.stdout
    try:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerow(["implementation", "class", "kind", "selector", "types"])
        for method in methods:
            writer.writerow(
                [
                    f"0x{method.implementation:08x}",
                    method.class_name,
                    method.kind,
                    method.selector,
                    method.types,
                ]
            )
    finally:
        if args.output:
            stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
