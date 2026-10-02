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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from listing_core import Lister  # noqa: E402

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
        # widen: every class whose init mentions shaderNamed: counts; the
        # render-name filter is kept as a flag for the narrow pass.
        if NARROW and not any("render" in s for s, _ in ms):
            continue
        imps = sorted(int(i, 16) for _, i in ms)
        for sel, imp in ms:
            if sel == "init" or sel.startswith("initWith"):
                lo = int(imp, 16)
                # the method's real end: the next IMP of the same class
                nxt = next((i for i in imps if i > lo), lo + 0x2000)
                rows.append((cls, sel, imp, lo, min(nxt, lo + 0x2000)))
    return rows


LISTER = None
NARROW = False


def sweep(elf: Path, tsv: Path, out: Path):
    global LISTER
    LISTER = Lister(elf)
    inits = class_inits(tsv)
    seen = set()
    results = []
    for cls, sel, imp, lo, hi in inits:
        if (cls, sel) in seen:
            continue
        seen.add((cls, sel))
        text = LISTER.emit(f"{cls} -[{sel}]", "v8@0:4", lo, hi)
        if SEL_REF not in text:
            continue
        # only the literals in the shaderNamed: call's own window — the
        # init bodies reference hundreds of unrelated strings (textures, UI
        # copy, sounds); the call's arguments live within the next few
        # hundred bytes, so bound the window to the following lines.
        lines = text.splitlines()
        sites = [i for i, l in enumerate(lines) if SEL_REF in l]
        # the compiler builds the argument arrays BEFORE loading the
        # selector, so the call's literals sit just before the site; a
        # method may build SEVERAL shaders (Weather: Snow + Rain), so scan
        # each call site's own backward window and merge the results.
        all_lits = []
        for i, site in enumerate(sites):
            # each call's own neighbourhood: clipped at the midpoints to the
            # neighbouring sites (a method may build several shaders).
            lo_ = (sites[i - 1] + site) // 2 if i else max(0, site - 200)
            hi_ = ((site + sites[i + 1]) // 2
                   if i + 1 < len(sites) else min(len(lines), site + 200))
            seg = "\n".join(lines[lo_:hi_])
            all_lits.extend(re.findall(
                r"CFString key obj @0x[0-9a-f]+ '([^']+)'", seg))
        seen_lit = set()
        dedup = []
        for lit in all_lits:
            if lit not in seen_lit:
                seen_lit.add(lit)
                dedup.append(lit)
        all_lits = dedup
        vsh = {p.stem for p in (ROOT / "reconstruction/reverse-v3/assets/shaders").glob("*.vsh")}
        start = next((i for i, s in enumerate(all_lits) if s in vsh), None)
        lits = []
        if start is not None:
            # shader/attribute/uniform names are bare identifiers; the first
            # filename or UI string ends the call's own literal run.
            for lit in all_lits[start:]:
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", lit):
                    lits.append(lit)
                else:
                    break
        # the shader file name is the first literal that matches a shipped
        # .vsh pair; the rest are the attributes and uniforms
        vsh = {p.stem for p in
               (ROOT / "reconstruction/reverse-v3/assets/shaders").glob("*.vsh")}
        shader = next((s for s in lits if s in vsh), None)
        if shader is None:
            results.append((cls, sel, imp, "?", "", ""))
            continue
        rest = [s for s in lits if s != shader]
        # classify by the shader SOURCE's declarations: the code builds the
        # argument arrays right-to-left (ARM), so raw order is unreliable,
        # but membership in the .vsh/.fsh attribute/uniform sets is exact.
        sh_dir = ROOT / "reconstruction/reverse-v3/assets/shaders"
        src = ""
        for ext in (".vsh", ".fsh"):
            p = sh_dir / (shader + ext)
            if p.exists():
                src += p.read_text() + "\n"
        # the declaration may carry a precision qualifier (uniform highp
        # vec4 color) — take the LAST identifier before the semicolon.
        decl_attr = set(re.findall(r"attribute[^;]*?(\w+)\s*;", src))
        decl_uni = set(re.findall(r"uniform[^;]*?(\w+)\s*;", src))
        attrs = [s for s in rest if s in decl_attr and s not in decl_uni]
        unis = [s for s in rest if s in decl_uni and s not in decl_attr]
        unknown = [s for s in rest if s not in decl_attr and s not in decl_uni]
        if unknown:
            attrs = attrs + ["?" + ",".join(unknown)]
        results.append((cls, sel, imp, shader,
                        ",".join(attrs), ",".join(unis)))
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
    ap.add_argument("--narrow", action="store_true",
                    help="only classes with a render* method (the old pass)")
    a = ap.parse_args()
    global NARROW
    NARROW = a.narrow
    sweep(a.elf, a.methods, a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
