#!/usr/bin/env python3
"""Sweep the class -> shader mapping.

Every render-capable class builds its shader through the same seam:
  [cache shaderNamed:@"<Name>" attributes:@[...] uniforms:@[...]]
So for each class's `initWith*` implementation the nearby CFString literals
give the mapping. This tool disassembles those inits (tools/emit_annotated_method.py,
which annotates CFString refs) and emits a TSV:

  class  method  imp  shader_name  attributes  uniforms

Host only (needs the ELF). The mapping for MJButton was proven by hand
three ways (SHADERS.md); this sweep extends it mechanically.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"

SEL_REF = "shaderNamed:attributes:uniforms:"


def class_inits(tsv: Path):
    """(class, selector, imp) for the initWith*/init rows of classes that
    actually render (they declare a renderFrame:/render: method), in file
    order. Scanning every class and its neighbours is needlessly slow."""
    rows = []
    per_class = {}
    for line in tsv.read_text().splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        imp, cls, kind, sel = parts[0], parts[1], parts[2], parts[3]
        if kind != "instance":
            continue
        per_class.setdefault(cls, []).append((sel, imp))
    for cls, ms in per_class.items():
        renders = any("render" in s for s, _ in ms)
        if not renders:
            continue
        for sel, imp in ms:
            if sel == "init" or sel.startswith("initWith"):
                rows.append((cls, sel, imp))
    return rows


def sweep(elf: Path, tsv: Path, out: Path):
    inits = class_inits(tsv)
    seen = set()
    results = []
    for cls, sel, imp in inits:
        if (cls, sel) in seen:
            continue
        seen.add((cls, sel))
        lo = int(imp, 16)
        # a generous window: the init body's first 0x1200 bytes
        tmp = NATIVE / f".sweep_{cls}.txt"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/emit_annotated_method.py"),
             f"{cls} -[{sel}]", "v8@0:4", hex(lo), hex(lo + 0x1200),
             str(tmp)],
            capture_output=True, text=True)
        if proc.returncode != 0 or not tmp.exists():
            continue
        text = tmp.read_text()
        tmp.unlink()
        if SEL_REF not in text:
            continue
        # only the literals in the shaderNamed: call's own window — the
        # init bodies reference hundreds of unrelated strings (textures, UI
        # copy, sounds); the call's arguments live within the next few
        # hundred bytes, so bound the window to the following lines.
        lines = text.splitlines()
        site = next(i for i, l in enumerate(lines) if SEL_REF in l)
        window = "\n".join(lines[site:site + 260])
        lits = re.findall(r"CFString key obj @0x[0-9a-f]+ '([^']+)'", window)
        # the shader file name is the first literal that matches a shipped
        # .vsh pair; the rest are the attributes and uniforms
        vsh = {p.stem for p in
               (ROOT / "reconstruction/reverse-v3/assets/shaders").glob("*.vsh")}
        shader = next((s for s in lits if s in vsh), None)
        if shader is None:
            results.append((cls, sel, imp, "?", "", ""))
            continue
        rest = [s for s in lits if s != shader]
        results.append((cls, sel, imp, shader,
                        ",".join(rest[:2]), ",".join(rest[2:])))
    out.write_text("class\tmethod\timp\tshader\tattributes\tuniforms\n"
                   + "\n".join("\t".join(r) for r in results) + "\n")
    print(f"wrote {out} ({len(results)} rows)")
    for r in sorted(results, key=lambda r: r[0]):
        print(f"  {r[0]:24s} {r[3]:24s} attrs[{r[4]}] uniforms[{r[5]}]")
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", type=Path)
    ap.add_argument("--methods", type=Path,
                    default=Path("/data/data/com.termux/files/home/.hermes/"
                                 "cache/scratch/all-methods.tsv"))
    ap.add_argument("--out", type=Path,
                    default=NATIVE / "shader_mapping.tsv")
    a = ap.parse_args()
    sweep(a.elf, a.methods, a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
