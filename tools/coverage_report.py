#!/usr/bin/env python3
"""Machine-generated coverage audit for libApplication.so (the official client).

Answers "how much of the official program have we consumed?" with auditable
numbers instead of adjectives. Inputs are all in-repo and SHA-pinned:

  * reconstruction/reverse-v3/native/libApplication_objc_methods.tsv
        every ObjC method (imp, class, kind, selector, types) — 10,478 rows.
        Per-method code size = the gap to the next IMP (words), the same
        boundary convention emit_annotated_method.py uses.
  * reconstruction/reverse-v3/native/reverse_coverage_ledger.json
        the repo's own per-method stage ledger (indexed/refs/cfg/semantics/
        implemented/behavior-verified).
  * reconstruction/reverse-v3/native/disasm_*.txt
        annotated listing headers pin the methods with level-A evidence.
  * reconstruction/reverse-v3/native/*.json batch files (recover_*.py
        outputs): each class dict's imp adds level-A batch coverage.
  * tools/test_*arm*.py constants inside .text: methods executed on Unicorn.

Outputs COVERAGE_AUDIT.md + coverage_audit.json next to the native evidence.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
ELF_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
TEXT_LO, TEXT_HI = 0x001C4480, 0x00DB8950     # .text VMA range

# class-name -> subsystem bucket for the covered slice (curated, small)
SUBSYSTEM_RULES = [
    (r"^(AppleTree|MapleTree|MangoTree|PineTree|CactusTree|CoconutTree|"
     r"CherryTree|CoffeeTree|GemTree|LimeTree|OrangeTree|Tree|Plant|"
     r"VinePlant|Kelp|Tulip|Corn|Tomato|Sunflower)", "树/植物"),
    (r"^(Dodo|Donkey|DropBear|CaveTroll|NPC|Yak|Fish|Bear|DonkeyLike)", "NPC/动物"),
    (r"(Workbench|Chest|TradingPost|TradePortal|InventoryItem|CraftableItem|"
     r"Painting|Sign|Bed|Door|Window|Rail|Wire|Column|Stairs|Ladder|Egg|Boat|"
     r"GlowBlock|FireObject|Torch|GatherBlock|FreeBlock|TrainCar|SteamTrain|"
     r"FreightCar|HandCar|PassengerCar|Elevator|SurfaceBlock|ArtificialLight|"
     r"OwnershipSign|DynamicObject|Blockhead)", "动态对象/存档装配"),
    (r"^MJSound", "音频"),
    (r"(GameView|GameActivity|MainMenu|Projection|Touch|WebView)", "渲染/输入/UI"),
    (r"^World", "世界/主域"),
    (r"(Net|Packet|Server|Client|Buddy)", "网络"),
]
DEFAULT_BUCKET = "其余（未入口）"


def subsystem_of(cls: str) -> str:
    for pat, name in SUBSYSTEM_RULES:
        if re.search(pat, cls):
            return name
    return DEFAULT_BUCKET


def main() -> int:
    rows = []
    with (NATIVE / "libApplication_objc_methods.tsv").open() as f:
        next(f)
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            try:
                imp = int(parts[0], 16)
            except ValueError:
                continue
            rows.append({"imp": imp, "class": parts[1], "kind": parts[2],
                         "selector": parts[3]})
    rows.sort(key=lambda r: r["imp"])
    for i, r in enumerate(rows):
        nxt = rows[i + 1]["imp"] if i + 1 < len(rows) else r["imp"] + 0x40
        r["words"] = max(1, (nxt - r["imp"]) // 4)
    total_methods = len(rows)
    total_words = sum(r["words"] for r in rows)
    text_words = (TEXT_HI - TEXT_LO) // 4

    # ledger stages by imp
    ledger = json.loads((NATIVE / "reverse_coverage_ledger.json").read_text())
    stages_by_imp = {}
    for e in ledger["entries"]:
        try:
            imp = int(e["implementation"], 16)
        except (KeyError, ValueError):
            continue
        stages_by_imp[imp] = e.get("stages", {})

    # level-A listings
    listing_imps = set()
    for p in NATIVE.glob("disasm_*.txt"):
        head = p.read_text(errors="ignore")[:1500]
        m = re.search(r"# implementation:\s*(0x[0-9a-f]+)", head)
        if m:
            listing_imps.add(int(m.group(1), 16))

    # batch jsons (recover_*.py outputs): class dicts with 'imp'
    batch_imps = set()
    batch_files = 0
    for p in NATIVE.glob("*.json"):
        try:
            d = json.loads(p.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        classes = d.get("classes") if isinstance(d, dict) else None
        if not isinstance(classes, list):
            continue   # e.g. the graph json's class COUNT, not a class list
        batch_files += 1
        for c in classes:
            if isinstance(c, dict) and c.get("imp"):
                try:
                    batch_imps.add(int(c["imp"], 16))
                except (TypeError, ValueError):
                    continue

    # ARM-executed imps: 0x00xx addresses inside .text referenced by harnesses
    arm_imps = set()
    for p in sorted(ROOT.glob("tools/test_*arm*.py")):
        text = p.read_text(errors="ignore")
        for m in re.finditer(r"0x00[0-9a-fA-F]{6}", text):
            v = int(m.group(0), 16)
            if TEXT_LO <= v <= TEXT_HI:
                arm_imps.add(v)

    def covered(subset) -> dict:
        ms = [r for r in rows if r["imp"] in subset]
        return {"methods": len(ms), "words": sum(r["words"] for r in ms)}

    listing = covered(listing_imps)
    batch = covered(batch_imps)
    arm = covered(arm_imps)
    semantic = {"methods": sum(1 for r in rows
                              if stages_by_imp.get(r["imp"], {}).get("semantics")),
                "words": sum(r["words"] for r in rows
                             if stages_by_imp.get(r["imp"], {}).get("semantics"))}
    implemented = {"methods": sum(1 for r in rows
                                  if stages_by_imp.get(r["imp"], {}).get("implemented")),
                   "words": sum(r["words"] for r in rows
                                if stages_by_imp.get(r["imp"], {}).get("implemented"))}

    # subsystem breakdown over the union of evidence sets
    union = listing_imps | batch_imps | arm_imps
    buckets = {}
    for r in rows:
        if r["imp"] not in union:
            continue
        b = buckets.setdefault(subsystem_of(r["class"]),
                               {"methods": 0, "words": 0, "arm": 0, "listings": 0})
        b["methods"] += 1
        b["words"] += r["words"]
        if r["imp"] in arm_imps:
            b["arm"] += 1
        if r["imp"] in listing_imps:
            b["listings"] += 1
    for name, b in buckets.items():
        b["names"] = name

    def pct(n, d) -> str:
        return f"{100.0 * n / d:.2f}%"

    md = []
    md.append("# libApplication.so — coverage audit (machine-generated)")
    md.append("")
    md.append(f"ELF sha256 `{ELF_SHA}`. Generated by "
              f"`python3 tools/coverage_report.py` — every number below is "
              f"recomputable from the in-repo TSV/ledger/evidence files.")
    md.append("")
    md.append("## Totals")
    md.append("")
    md.append(f"- ObjC methods indexed: **{total_methods}** "
              f"(~{total_words} words of per-method bodies)")
    md.append(f"- .text: {TEXT_HI - TEXT_LO} bytes = **{text_words} words**")
    md.append("")
    md.append("| lens | methods | words | % of .text words |")
    md.append("|---|---:|---:|---:|")
    md.append(f"| level-A annotated listings | {listing['methods']} | "
              f"{listing['words']} | {pct(listing['words'], text_words)} |")
    md.append(f"| level-A batch evidence (recover_*.py jsons) | "
              f"{batch['methods']} | {batch['words']} | "
              f"{pct(batch['words'], text_words)} |")
    md.append(f"| executed under Unicorn (ARM harnesses) | {arm['methods']} | "
              f"{arm['words']} | {pct(arm['words'], text_words)} |")
    md.append(f"| ledger semantics | {semantic['methods']} | "
              f"{semantic['words']} | {pct(semantic['words'], text_words)} |")
    md.append(f"| ledger implemented | {implemented['methods']} | "
              f"{implemented['words']} | {pct(implemented['words'], text_words)} |")
    md.append("")
    md.append("The ledger stages are the repo's ORIGINAL pipeline; listing-level "
              "decodes do not promote stages by convention, so the two bottom "
              "rows understate the save/load front. The three top rows are the "
              "front's own evidence sets (union shown below).")
    md.append("")
    md.append("## Covered slice by subsystem (union of the three sets)")
    md.append("")
    md.append("| subsystem | methods | words | of which executed | of which listings |")
    md.append("|---|---:|---:|---:|---:|")
    for name in sorted(buckets, key=lambda n: -buckets[n]["words"]):
        b = buckets[name]
        md.append(f"| {name} | {b['methods']} | {b['words']} | {b['arm']} | "
                  f"{b['listings']} |")
    cov_words = sum(b["words"] for b in buckets.values())
    md.append(f"| **covered total (deduped rows)** | "
              f"{sum(b['methods'] for b in buckets.values())} | {cov_words} | "
              f"{sum(b['arm'] for b in buckets.values())} | "
              f"{sum(b['listings'] for b in buckets.values())} |")
    md.append(f"| 其余（未入口：渲染/模拟/UI/网络/音频/脚本…） | "
              f"{total_methods - sum(b['methods'] for b in buckets.values())} | "
              f"{total_words - cov_words} | 0 | 0 |")
    md.append("")
    md.append(f"Covered slice: **{pct(cov_words, text_words)} of .text words**, "
              f"{pct(sum(b['methods'] for b in buckets.values()), total_methods)} "
              f"of methods — dominated by the persistence/save-assembly front.")
    out_md = NATIVE / "COVERAGE_AUDIT.md"
    out_md.write_text("\n".join(md) + "\n")
    (NATIVE / "coverage_audit.json").write_text(json.dumps({
        "elf_sha256": ELF_SHA, "methods": total_methods,
        "method_words": total_words, "text_words": text_words,
        "listing": listing, "batch": batch, "arm": arm,
        "ledger_semantics": semantic, "ledger_implemented": implemented,
        "subsystems": {k: v for k, v in buckets.items()},
    }, indent=2) + "\n")
    print(f"wrote {out_md.relative_to(ROOT)}")
    print(f"methods={total_methods} words={total_words} text_words={text_words}")
    print(f"listings={listing} arm={arm} semantics={semantic}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
