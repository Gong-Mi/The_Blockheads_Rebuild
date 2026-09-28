# Automation pipeline (how the hand-work got replaced)

Five generators, all over the SHA-pinned ELF or the in-repo evidence, each with
a CI guard. Order of use for a new class:

1. **`tools/elf_class_metadata.py`** — class table straight from the ELF
   (`__objc_classlist` / `__objc_const` / `__objc_ivar` / `__objc_superrefs`):
   536 classes, supers, instance sizes, ivar layouts (name/offset/type),
   superref cells. → `class_metadata.json` + `CLASS_TABLE.md`.
   Replaces: hand-mining ivar offsets and superref cells from listings.

2. **`tools/class_graph.py`** — composition graph: super edges, containment
   (`owns`) edges from ivar object types, the 64-type table, listing classref
   mentions, curated construction edges (each quoting its claim). →
   `OBJECT_GRAPH.md` + `object_graph.json`.
   Replaces: reading claims files one by one to know who contains/constructs
   what. The open-boundary list (owns-edge from a recovered class to an
   unreached class) is a mechanical completeness checklist.

3. **`tools/emit_annotated_method.py`** — annotated listing for one method
   (capstone + literal-cell resolution; coverage gate). The listing is still
   the human-readable artifact, but everything machine-derivable now comes
   from 1/2/4 instead.

4. **`tools/test_specials_arm.py --emit-spec <Class>`** — EXECUTION-based key
   table extraction: run the original body under Unicorn with the msgSend
   stub graph, hook the instance memory writes (`UC_HOOK_MEM_WRITE`), and zip
   the k-th conversion from the call trace with the k-th instance write →
   `{key, conv, width, offset, value}` rows (writes before any conversion are
   emitted as `defaults`, e.g. Boat's -1 and OwnershipSign's 15). This is
   what used to be eyeballed from listings — and the same run that produced
   the listing-order mistakes the differentials later caught. The tables for
   every harness ENTRIES row are extractable this way; the pinned models in
   the bridges are then checked against the ARM runs.

5. **`tools/coverage_report.py`** — the accounting: methods/words per evidence
   lens (listings, batch jsons, ARM-executed, ledger) and a subsystem
   breakdown, vs the 3,133,748 words of `.text`. → `COVERAGE_AUDIT.md`.

Guards: `test_class_graph.py` (floors + the ten pinned superref cells
cross-checked against the metadata), `test_specials_arm_evidence.py` (pinned
constants incl. the decode corrections), `test_midtier_arm_evidence.py`,
`test_forwarder5b_arm_evidence.py`, `test_coverage_audit.py` (grow-only
floors). All CI-safe: they verify committed artifacts when the ELF is absent
and regenerate when it is present.

## Source-size estimate (for planning)

Measured words→lines ratios from the faithful ports: 0.30 (InteractionObject
105 lines / 352 words), 0.22 (NPC loadValues 133 / 603), 0.19 (repo-wide
modules 10,754 / 56,861 covered words).

| style | ratio | full program (3.10M method words) |
|---|---|---|
| 1:1 faithful | 0.25-0.30 | ~0.8-0.9M lines |
| this repo's behavioural/table style | ~0.19 | ~0.6M lines (cross-check: 1.07M... 10.7K lines = 1.81% of .text → ~0.59M) |
| minimal table-driven | ~0.10 | ~0.3M lines |

Current reconstruction: 10,754 module lines + 8,479 test lines ≈ 1-2% of the
projected tree, concentrated on the persistence/save-assembly front. Excludes
assets (the APK carries ~70MB) and data tables (.rodata 275KB).
