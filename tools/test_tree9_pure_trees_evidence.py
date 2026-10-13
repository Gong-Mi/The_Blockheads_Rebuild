#!/usr/bin/env python3
"""Guard for the treefamily9 pure-tree evidence (see
reconstruction/reverse-v3/native/TREEFAMILY9_PURE_TREES.md).

CI mode (no ELF): asserts the recorded constants in the evidence note and
the expected registrations exist.
Host mode (--elf <pinned libApplication.so>): recomputes the GetSaveDict
body hashes and the 25-word core hash from the ELF and compares them to
the recorded constants (schema pinned by SHA-256 of the ELF itself).
"""
import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTE = ROOT / "reconstruction/reverse-v3/native/TREEFAMILY9_PURE_TREES.md"
ELF_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
CORE25_SHA = "af5a10bb83973043a15b66c336f99b112a3c348d0c8234e2cec88d0129d2a30c"
BODIES = [
    ("OrangeTree", 0x00a966fc, 31, "be3931695ea10363f1b9c54b482d8a5b"),
    ("CoconutTree", 0x00a99ab4, 31, "cff3ea8876dcb097a020da0ba9b22e58"),
    ("CherryTree", 0x00d0e024, 31, "9a1c8df4dc6347701c035ed24da37118"),
    ("MangoTree", 0x00d4b5ec, 31, "c2e463543eb1c9376a7d455c259a242d"),
    ("MapleTree", 0x00db60ac, 31, "a56c49952e14ade8d249611a155d051c"),
    ("CoffeeTree", 0x007dec20, 32, "950c23c3f4c304557a1d9c33c3a2ef00"),
    ("LimeTree", 0x00809d34, 31, "e10850965d407c564aca3e66e40d952d"),
]


def recorded_constants_ok() -> bool:
    text = NOTE.read_text()
    if CORE25_SHA not in text:
        print("evidence note misses the core-25 sha")
        return False
    for name, imp, words, sha in BODIES:
        if f"{imp:#010x}" not in text or sha not in text:
            print(f"evidence note misses {name} row ({imp:#x})")
            return False
    return True


def recompute(elf_path: Path) -> bool:
    if hashlib.sha256(elf_path.read_bytes()).hexdigest() != ELF_SHA:
        print("ELF SHA mismatch against the pinned binary")
        return False
    from elftools.elf.elffile import ELFFile

    ok = True
    with elf_path.open("rb") as f:
        elf = ELFFile(f)
        secs = [(s["sh_addr"], s["sh_offset"], s["sh_size"])
                for s in elf.iter_sections() if s["sh_flags"] & 0x2]

        def read(vaddr: int, n: int) -> bytes:
            for addr, off, size in secs:
                if addr <= vaddr and vaddr + n * 4 <= addr + size:
                    f.seek(off + (vaddr - addr))
                    return f.read(n * 4)
            raise SystemExit(f"vaddr {vaddr:#x} outside loadable sections")

        for name, imp, words, sha in BODIES:
            body = read(imp, words)
            got_full = hashlib.sha256(body).hexdigest()[:32]
            got_core = hashlib.sha256(body[: 25 * 4]).hexdigest()
            if got_full != sha:
                print(f"{name}: full-body sha mismatch {got_full}")
                ok = False
            if got_core != CORE25_SHA:
                print(f"{name}: core-25 sha mismatch {got_core}")
                ok = False
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path)
    a = ap.parse_args()
    if not recorded_constants_ok():
        return 1
    if a.elf is not None:
        if not recompute(a.elf):
            return 1
        print("tree9-pure-trees: PASS (ELF recomputation matches the note)")
        return 0
    print("tree9-pure-trees: PASS (constants; run with --elf to recompute)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
