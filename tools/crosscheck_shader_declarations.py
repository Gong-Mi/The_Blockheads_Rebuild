#!/usr/bin/env python3
"""Cross-check the shader mapping table against the shipped shader sources.

`shader_mapping.tsv` records, per class/method, which shader a UI class uses and
what its attribute/uniform cells say. Those cells are not a declaration list: they
mix attribute names with binding markers, e.g.

    attributes = ?color,ColoredNoTexture
    attributes = position,?StandardObject,texture,texCoord
    uniforms   = mvp_matrix,color,texture

`texture` and `ColoredNoTexture` are not declared anywhere in the .vsh/.fsh
sources (`Block.vsh` declares position/texCoord/other/paintColor), so reading the
cell as "the attributes this shader has" would be wrong. This tool classifies each
token instead:

    declared-attribute   the token is an `attribute` in that shader's source
    declared-uniform     the token is a `uniform` in that shader's source
    optional-declared    the token was marked `?` in the mapping and is declared
    undeclared           the token is neither - a binding marker or a constant,
                         recorded as such rather than counted as a mismatch

Usage:
  python3 tools/crosscheck_shader_declarations.py <assets-root> <shader_mapping.tsv> \
      [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

DECL_RE = re.compile(r"^\s*(attribute|uniform)\s+\w+\s+([A-Za-z_]\w*)")


def parse_declarations(root: Path) -> dict[str, dict[str, set[str]]]:
    out: dict[str, dict[str, set[str]]] = {}
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in (".vsh", ".fsh"):
            continue
        entry = out.setdefault(path.stem, {"attribute": set(), "uniform": set()})
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            match = DECL_RE.match(line)
            if match:
                entry[match.group(1)].add(match.group(2))
    return out


def classify_tokens(cell: str, declared: dict[str, set[str]]) -> list[dict]:
    tokens = []
    for raw in (cell or "").split(","):
        token = raw.strip()
        if not token:
            continue
        optional = token.startswith("?")
        name = token.lstrip("?")
        if name in declared["attribute"]:
            kind = "optional-declared" if optional else "declared-attribute"
        elif name in declared["uniform"]:
            kind = "optional-declared" if optional else "declared-uniform"
        else:
            kind = "undeclared"
        tokens.append({"token": name, "optional": optional, "class": kind})
    return tokens


def build(assets: Path, mapping: Path) -> dict:
    declared = parse_declarations(assets)
    with mapping.open(newline="", encoding="utf-8") as fh:
        mapping_rows = list(csv.DictReader(fh, delimiter="\t"))

    rows = []
    claimed_anywhere: dict[str, set[str]] = collections.defaultdict(set)
    for row in mapping_rows:
        shader = (row.get("shader") or "").strip()
        decl = declared.get(shader, {"attribute": set(), "uniform": set()})
        attr_tokens = classify_tokens(row.get("attributes", ""), decl)
        uniform_tokens = classify_tokens(row.get("uniforms", ""), decl)
        for token in attr_tokens:
            claimed_anywhere[shader].add(token["token"])
        rows.append({
            "class": row.get("class", ""),
            "method": row.get("method", ""),
            "shader": shader,
            "shader_files_present": shader in declared,
            "declared_attributes": sorted(decl["attribute"]),
            "declared_uniforms": sorted(decl["uniform"]),
            "attribute_tokens": attr_tokens,
            "uniform_tokens": uniform_tokens,
            "undeclared_tokens": sorted(
                t["token"] for t in attr_tokens + uniform_tokens if t["class"] == "undeclared"),
        })

    token_classes = collections.Counter(
        t["class"] for r in rows for t in r["attribute_tokens"] + r["uniform_tokens"])
    never_claimed = {}
    for shader, decl in sorted(declared.items()):
        unclaimed = sorted(decl["attribute"] - claimed_anywhere.get(shader, set()))
        if unclaimed:
            never_claimed[shader] = unclaimed
    return {
        "schema": 1,
        "assets_root": str(assets),
        "mapping": {"path": mapping.name,
                    "sha256": hashlib.sha256(mapping.read_bytes()).hexdigest()},
        "claim": ("shader mapping cells vs the shipped shader sources: every token "
                  "classified as a declared attribute/uniform, an optional-declared "
                  "one, or a binding marker (undeclared) - never silently treated "
                  "as a declaration"),
        "counts": {
            "mapping_rows": len(rows),
            "shaders_referenced": len({r["shader"] for r in rows}),
            "shaders_missing_source": sum(1 for r in rows if not r["shader_files_present"]),
            "tokens": sum(token_classes.values()),
            "declared_attribute": token_classes.get("declared-attribute", 0),
            "declared_uniform": token_classes.get("declared-uniform", 0),
            "optional_declared": token_classes.get("optional-declared", 0),
            "undeclared_binding_markers": token_classes.get("undeclared", 0),
            "rows_with_undeclared_tokens": sum(1 for r in rows if r["undeclared_tokens"]),
            "declared_attributes_never_claimed": sum(len(v) for v in never_claimed.values()),
        },
        "never_claimed_attributes": never_claimed,
        "rows": rows,
    }


TSV_FIELDS = ["class", "method", "shader", "shader_files_present", "declared_attributes",
              "attribute_tokens", "declared_uniforms", "uniform_tokens",
              "undeclared_tokens"]


def render_tsv(rows: list[dict]) -> str:
    def cell(value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            parts = []
            for item in value:
                if isinstance(item, dict):          # a classified token
                    parts.append(("?" if item.get("optional") else "") + str(item.get("token")))
                else:
                    parts.append(str(item))
            return ",".join(parts)
        return str(value)

    lines = ["\t".join(TSV_FIELDS)]
    for row in rows:
        lines.append("\t".join(cell(row.get(f)) for f in TSV_FIELDS))
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=Path)
    ap.add_argument("mapping", type=Path)
    default_native = Path("reconstruction/reverse-v3/native")
    ap.add_argument("--tsv", type=Path,
                    default=default_native / "shader_declaration_crosscheck.tsv")
    ap.add_argument("--json", type=Path,
                    default=default_native / "shader_declaration_crosscheck.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.assets, args.mapping)
    tsv = render_tsv(record["rows"])
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        status = 0
        for path, expected in ((args.tsv, tsv), (args.json, payload)):
            if not path.exists():
                print(f"CHECK FAILED: {path} is missing", file=sys.stderr)
                status = 1
            elif path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} is stale", file=sys.stderr)
                status = 1
        if status == 0:
            print(f"check ok: {record['counts']}")
        return status
    args.tsv.parent.mkdir(parents=True, exist_ok=True)
    args.tsv.write_text(tsv, encoding="utf-8")
    args.json.write_text(payload, encoding="utf-8")
    print(f"wrote {args.tsv.name} + {args.json.name}: {record['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
