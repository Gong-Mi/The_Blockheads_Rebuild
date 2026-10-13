#!/usr/bin/env python3
"""Build the class composition graph for libApplication.so.

Inputs (all machine-readable, in-repo):
  * native/class_metadata.json   (tools/elf_class_metadata.py output)
        class -> superclass, instance size, ivar layouts (name/offset/type)
  * native/dynamicobject_type_matrix.json   type id -> class name
  * native/disasm_*.txt          annotated listings: owning class + the
        OBJC_CLASS_$_X classrefs a method mentions (a mention is an evidence
        POINTER, not a construction proof; alloc-adjacent mentions are
        flagged may_construct)

Edges emitted:
  super       class -> superclass              (authoritative, metadata)
  owns        class -> ivar object type         (authoritative, metadata;
              arrays [N@"X"] count as N owns-entries)
  typed       64-type table: type id -> class   (the record domain)
  mentions    class -(method)-> referenced class (from the listings)

Outputs native/OBJECT_GRAPH.md + native/object_graph.json.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"

OBJ_RE = re.compile(r'@"([A-Za-z_][A-Za-z0-9_]*)"')
ARR_RE = re.compile(r'\[(\d+)@"([A-Za-z_][A-Za-z0-9_]*)"\]')


def main() -> int:
    meta = json.loads((NATIVE / "class_metadata.json").read_text())
    classes = meta["classes"]
    typemap = json.loads((NATIVE / "dynamicobject_type_matrix.json").read_text())
    type_rows = typemap["types"]

    nodes = {}
    super_edges = []
    owns_edges = []
    for name, c in classes.items():
        nodes[name] = {"instance_size": c["instance_size"],
                       "ivars": len(c["ivars"])}
        if c["super"]:
            super_edges.append({"from": name, "to": c["super"]})
        for iv in c["ivars"]:
            t = iv["type"]
            for cnt, target in ARR_RE.findall(t):
                owns_edges.append({"from": name, "to": target,
                                   "ivar": iv["name"], "offset": iv["offset"],
                                   "count": int(cnt)})
            for target in OBJ_RE.findall(t):
                # skip the array form (already counted above)
                if f'@"{target}"' in t and ARR_RE.search(t):
                    continue
                owns_edges.append({"from": name, "to": target,
                                   "ivar": iv["name"], "offset": iv["offset"],
                                   "count": 1})

    typed_edges = [{"type_id": r["type_id"], "class": r["class_name"]}
                   for r in type_rows]

    # mentions from the annotated listings
    mention_edges = []
    for p in sorted(NATIVE.glob("disasm_*.txt")):
        text = p.read_text(errors="ignore")
        head = re.search(r"#\s*([A-Za-z_][A-Za-z0-9_]*)\s*-\[([^\]]+)\]", text)
        if not head:
            continue
        owner, sel = head.group(1), head.group(2)
        refs = sorted(set(re.findall(r"OBJC_CLASS_\$_([A-Za-z_][A-Za-z0-9_]*)", text)))
        may_construct = "SEL=alloc" in text
        for r in refs:
            mention_edges.append({"from": owner, "method": sel, "to": r,
                                  "may_construct": may_construct})

    # ---- report ----
    game_types = {r["class_name"]: r["type_id"] for r in type_rows}
    dynamic_classes = [c for c in typed_edges]
    # the dynamic-object tree: walk supers upward for each typed class
    tree_lines = []
    def chain(name, depth=0, seen=None):
        seen = seen or set()
        if name in seen or depth > 8:
            return
        seen.add(name)
        node = classes.get(name)
        if not node:
            return
        typ = f" (type {game_types[name]})" if name in game_types else ""
        tree_lines.append(f"{'  ' * depth}- {name}{typ} "
                          f"[size {node['instance_size']}, "
                          f"ivars {len(node['ivars'])}]")
        kids = sorted(e["from"] for e in super_edges if e["to"] == name
                      and e["from"] in game_types)
        for k in kids:
            chain(k, depth + 1, seen)
    typed_names = {r["class"] for r in typed_edges}
    sup_of = {e["from"]: e["to"] for e in super_edges}
    for r in sorted(typed_edges, key=lambda x: x["type_id"]):
        anc, seen2, has_typed_ancestor = sup_of.get(r["class"]), set(), False
        while anc and anc not in seen2:
            if anc in typed_names:
                has_typed_ancestor = True
                break
            seen2.add(anc)
            anc = sup_of.get(anc)
        if has_typed_ancestor:
            continue          # printed under its typed ancestor
        chain(r["class"])

    # containment highlights for the dynamic classes
    def owns_of(name):
        return sorted({(e["to"], e["ivar"], e["count"]) for e in owns_edges
                       if e["from"] == name})
    # who constructs whom (may_construct mentions among game classes)
    constructs = {}
    for e in mention_edges:
        if e["may_construct"] and e["to"] in game_types:
            constructs.setdefault(e["from"], set()).add(e["to"])

    md = ["# Object graph — inheritance / containment / references "
          "(machine-generated)", "",
          f"Generated by `tools/class_graph.py` from class_metadata.json "
          f"({len(classes)} classes), the 64-type table and the annotated "
          f"listings.", "",
          "## Counts", "",
          f"- classes: {len(classes)}; with ivars: "
          f"{sum(1 for c in classes.values() if c['ivars'])}",
          f"- super edges: {len(super_edges)}; owns edges: {len(owns_edges)}; "
          f"type-table edges: {len(typed_edges)}; listing mentions: "
          f"{len(mention_edges)}",
          "", "## Dynamic-object inheritance tree (typed classes)", ""]
    md += tree_lines
    md += ["", "## Containment (owns) for the dynamic classes", "",
           "| class | owns |", "|---|---|"]
    for r in sorted(typed_edges, key=lambda x: x["type_id"]):
        o = owns_of(r["class"])
        if not o:
            continue
        cells = ", ".join(f"{t} x{c} ({iv})" if c > 1 else f"{t} ({iv})"
                          for t, iv, c in o)
        md.append(f"| {r['class']} | {cells} |")
    md += ["", "## Construction evidence (listing mentions with alloc present)",
           "", "| class | may construct |", "|---|---|"]
    for owner in sorted(constructs):
        md.append(f"| {owner} | {', '.join(sorted(constructs[owner]))} |")
    curated = json.loads((NATIVE / "construction_edges.json").read_text())
    md += ["", "## Construction relations (curated from evidence claims)",
           "", "| from | to | via | source |", "|---|---|---|---|"]
    for e in curated["edges"]:
        md.append(f"| {e['from']} | {e['to']} | {e['via']} | `{e['source']}` |")

    out_md = NATIVE / "OBJECT_GRAPH.md"
    out_md.write_text("\n".join(md) + "\n")
    (NATIVE / "object_graph.json").write_text(json.dumps({
        "classes": len(classes), "super_edges": super_edges,
        "owns_edges": owns_edges, "typed_edges": typed_edges,
        "mentions": mention_edges,
        "construction_edges": curated["edges"],
    }, indent=2) + "\n")
    print(f"wrote {out_md.relative_to(ROOT)}")
    print(f"classes={len(classes)} super={len(super_edges)} "
          f"owns={len(owns_edges)} typed={len(typed_edges)} "
          f"mentions={len(mention_edges)} constructors={len(constructs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
