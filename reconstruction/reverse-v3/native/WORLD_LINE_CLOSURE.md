# World-line closure — final statement (E14–E44 reverse / E45–E63 equivalence)

This document closes the WorldTileLoader + DynamicWorld work line. It states
the exact coverage, the remaining bodies, and the boundary artifacts.

## Reverse-evidence coverage (JSON-verified)

Method map: `libApplication_objc_methods.tsv`; coverage counted as "the
method's IMP appears in at least one recovered artifact JSON under
reconstruction/reverse-v3/native/".

| class | covered | total | percent |
|---|---:|---:|---:|
| WorldTileLoader | 51 | 52 | 98.1% |
| DynamicWorld | 209 | 210 | 99.5% |
| **World line** | **260** | **262** | **99.2%** |

The ledger counters (refs / cfg) additionally include the arm64 CFG line and
the pre-existing broad disasm dumps; they stood at refs 708 / cfg 707 at the
E43/E44 plateau point (see the metric notes in those commits for why the
broad `disasm_dw_*` dumps pre-count some IMPs).

## The two remaining bodies (with reasons)

1. **`-[WorldTileLoader compressBlocks]` (0x0085475c)** — not yet read. The
   remaining WTL body; suitable for a future batch (medium size, block
   compression path).
2. **`-[DynamicWorld .cxx_construct]` (0x00907218)** — the ~15,050-word
   compiler-generated member-constructor; classified as a **boundary
   artifact** since the E29-era work (as is the ~7,200-word
   `draw:...:hideUIType:` composite, which E44 landed as a structural pass
   rather than a full transcription).

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
