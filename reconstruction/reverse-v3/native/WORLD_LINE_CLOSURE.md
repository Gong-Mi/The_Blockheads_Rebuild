# World-line closure — final statement (E14–E44 reverse / E45–E63 equivalence)

This document closes the WorldTileLoader + DynamicWorld work line. It states
the exact coverage and the boundary artifacts. **Status update (E65/E66):
both formerly-remaining bodies are now closed — the line stands at 262/262
rows touched.**

## Reverse-evidence coverage (JSON-verified)

Method map: `libApplication_objc_methods.tsv`; coverage counted as "the
method's IMP appears in at least one recovered artifact JSON under
reconstruction/reverse-v3/native/".

| class | covered | total | percent |
|---|---:|---:|---:|
| WorldTileLoader | 52 | 52 | 100% |
| DynamicWorld | 210 | 210 | 100% |
| **World line** | **262** | **262** | **100% row-touched** |

The ledger counters (refs / cfg) additionally include the arm64 CFG line and
the pre-existing broad disasm dumps; they stood at refs 708 / cfg 707 at the
E43/E44 plateau point (see the metric notes in those commits for why the
broad `disasm_dw_*` dumps pre-count some IMPs).

## The two formerly-remaining bodies (now closed)

1. **`-[WorldTileLoader compressBlocks]` (0x0085475c)** — landed in **E65**:
   an empty 5-word stub (prologue/epilogue only; COMPRESS_STUB.md).
2. **`-[DynamicWorld .cxx_construct]` (0x00907218)** — landed in **E66 as a
   full read**: 866 instructions (the earlier "~15,050" figure was a
   listing-text word count, not instructions; CXX_CONSTRUCT.md carries the
   member-constructor inventory). The `draw:...:hideUIType:` composite (E44)
   remains the line's structural pass.

World line: **262/262 rows touched** (WTL 52/52 + DynamicWorld 210/210).

## Batch inventory (all CI-green at exact head, per-batch PR comments)

- Reverse line: **E14–E44** (31 batches) — physical-block save/migration/
  load, world construction, WTL closure, dynamic-object load chain and
  leaves, net sync, world save, change propagation, object lifecycle, draw/
  reload, mutation, breeding/NPC, client session, reload tail, placement,
  load/session, remote receive, users/bans, query/accessors, block-load,
  typed accessor families A–C, workbench/interaction, save/remote/simulate,
  draw cluster, final/last smalls, giant draw composite (structural pass).
- Equivalence line: **E45–E63** (19 batches) — 18 slices + the slice index +
  the cross-slice scenario (see reconstruction/recovered/README.md and
  WORLD_LINE_EQUIV_PLAN.md). Three fidelity errors were caught by the slice
  tests (E23 gate scope; E60 registry-face sync; E63 no-cell-leg removal).

## Standing boundaries

- Evidence levels: source/listing (A/B) define contracts; D hypotheses stay
  isolated and labelled; no runtime-equivalence claim without a differential
  oracle.
- The equivalence slices model closed contracts only; container classes,
  wire marshalling and objc dispatch bodies stay out of scope.
- Metric caveats: (a) refs/cfg can be pre-counted by broad early dumps —
  the JSON coverage above is the verified measure; (b) the level-A listing
  counter deduplicates by IMP.
