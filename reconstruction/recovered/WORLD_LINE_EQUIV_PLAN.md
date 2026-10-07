# World-line equivalent-code plan (E14–E23 → recovered C++ slices)

Status: preparation. This maps the reverse-v3 native evidence batches (E14–E23,
the WorldTileLoader / DynamicWorld line) onto behavior-equivalent C++ slices in
`reconstruction/recovered/`, following the existing slice conventions (one
static library per closed contract, batch comments in CMakeLists, C++17,
`-Wall -Wextra -Werror -ffp-contract=off`, tests under `tools/test_*.cpp`).

Rules (REVERSE_V3.md): only A/B evidence may define an equivalent contract; D
hypotheses stay isolated and labelled. A slice may model a closed contract; it
must not claim runtime equivalence with the original binary unless a differential
oracle exists.

## Readiness grading

- **T1 (table/formula exact)**: values pinned byte-exactly; can be encoded now.
- **T2 (closed behavior)**: control flow and flags pinned in the batch; can be
  encoded with documented boundaries.
- **T3 (open boundaries)**: micro-order or member roles still unestablished;
  encode the documented subset only, keep boundaries in comments.
- **T4 (not ready)**: needs further reading or a runtime experiment.

## Mapping

| batch | evidence artifact | equivalent candidate | grade |
|---|---|---|---|
| E14 | physical-block save/sync bodies | `physical_block_save_flags` (savePhysicalBlock flag truth table) | T2 |
| E15 | block-format migration ladder | `block_format_version_ladder` (versionOneToTwo..latest + `+0xd=8`) | T2 |
| E16 | block-load orchestrator | `makeIntpair` / quarter-column addressing helpers; version byte write | T1 |
| E17 | `initWithWorld:…` (10857 w) | height-array alloc shape (`calloc(count<<5,4)` ×3), tree/plant block-id tables, `xFrequencyMultiplier/yHeightDivider` naming | T1/T2 |
| E18 | WorldTileLoader closure | (no code: accessors/dealloc) | — |
| E19 | dynamic-object load chain | `dynamic_object_version_dispatch` (<2/2-5/6/7/≥8 ladder + tree-promise 64B pool) | T2 |
| E20 | load-chain leaves | `tree_plant_type_tables` (11/10 classes), `treasure_rarity_ladder` (8 tiers), FreeBlock/NPC caps (5000/512) | T1 |
| E21 | net-sync cluster | `dynamic_object_net_gates` (65-slot phases as a state contract); needsRemoved clearing | T3 |
| E22 | world-save cluster | `world_change_queues` (**landed, this plan's first slice**); five-container sweep contract | T2 |
| E23 | change propagation + sim | `sow_scan` (±2 occupancy scans, tile predicates); switch-table parity notes | T2/T3 |

## First slice landed

`reconstruction/recovered/world_change_queues.{h,cpp}` + `tools/test_world_change_queues.cpp`.

- Producer: `worldChangedAtPos:sendReliably:` (E22) — exact-position dedup gates
  only the ffffe5b8 push; macro routing (÷32 via `__aeabi_idiv` semantics +
  `makeIntpair`) runs on every call; reliable/unreliable queue split.
- `waterChangedAtPos:fullBlock:` (E23) queue part — water-position vector gated by
  fullBlock; macro routing always.
- `lightChangedAtMacroPos:sendReliably:sendAtAll:` (E23) queue part — macro input;
  third queue (ffffe57c) exposed but not wired (consumer role unestablished).
- Consumer: `saveAndSendOnlyBlocksThatNeedToBeSent` (E21) flush — server gate,
  pass 1 (sendReliably=1, dontSend=0, onlySaveIfClientsNeedIt=1), pass 2
  (sendReliably=0, dontSend=0, onlySaveIfClientsNeedIt=1), erase-on-success.
- Tests: dedup/routing, water gate, macro-input routing, flush order + flags +
  keep-on-zero. Compiled O0 and O2 with `-Werror -ffp-contract=off`.

The test suite caught one real fidelity error during preparation (an early
`return` on the exact-dedup path that the E22 listing contradicts: the dedup
gates only the push, the macro section always runs — `bne 0x8dfac8`). Fixed in
the slice; recorded here because the error class (gate scope) will recur across
T2 slices.

## Build pitfalls (CI recovered lane)

- The lane compiles with `g++ -Werror`; a `//` comment line ending in a backslash
  is `-Werror=comment` (multi-line comment) on GCC even though clang accepts it.
  Never put trailing backslashes in comments of files compiled by the lane; keep
  the build command one line per argument instead.
- Tests must run with asserts active: the lane compiles the direct `c++` steps
  without `-DNDEBUG`; CMake-registered tests use `-UNDEBUG`.

## Next slices (priority order)

1. `world_change_queues` stage 2: wire `thirdMacroQueue` once its consumer is
   established from a further controlled read (E23 574/57c micro-order).
2. `tree_plant_type_tables` (E20): exact class/type tables + switch-parity
   (E23 tables 0xE49A64/0xE4AA3C) as static arrays with batch anchors.
3. `treasure_rarity_ladder` (E20): 8-tier table + chest/troll constants.
4. `block_format_version_ladder` (E15/E19): pure decision function.
5. `sow_scan` (E23): occupancy predicate refactor shared by sowTree/sowPlant
   (±2 scan, `tileIsAirWaterOrSnow`, below-tile height gates 16/8, type-6/7
   specials).

Each slice lands as its own commit with tests run at O0/O2 and registered in
`reconstruction/recovered/CMakeLists.txt` with the batch comment style.

---

# Extension: E24–E44 batches into equivalent slices (E45 batch)

The World-line evidence batches continued past E23 (E24–E44, ~30 batches:
object query/lifecycle, draw/reload, world mutate, breed/NPC, client session,
reload tail, placement actions, load/session, remote receive, users/bans,
query/accessors, block-load, typed accessor families A–C, workbench/
interaction, save/remote/simulate, draw cluster, final/last smalls, and the
giant draw composite as a structural pass). Mapping of the load-bearing
contracts:

| batch range | evidence artifact | equivalent candidate | grade |
|---|---|---|---|
| E36 | accessor_a.json | type codes fire 16 / torch 17 / egg 30 / painting 52; the ffe235f0 / ffe23624 / ffe23600 triplet cells | T1 |
| E37 | accessor_b.json | ladder 19 / column 53 / stairs 54 / shaft 56 | T1 |
| E38 | accessor_c.json | window 31 / door 20; the 0x46 tile-marker write; pos then y−1 probe; boat +0x180 slice | T2 |
| E39 | workbench_interaction.json | workbench 45; the fffe234ac gate reuse; ffffe560 ID counter | T2 |
| E40 | save_remote_sim.json | 0x2e/0x18 save skips; 0xe FreeBlock remote skip; dt/8.0 family step | T2 |
| E41/E44 | draw_pass.json / draw_composite.json | the ffe23538/fee2353c dispatch unifications; the +0xa8 slice; <<11 macro maths | T3 |
| E43 | last_smalls.json | rail 40; motor 55 (ffe23640 pair with E23); 0xE4AA64 11-arm tree table | T1/T2 |
| E24/E30/E31/E33 | object_life/placement/load_session/users_bans | the ffffe550/ffffe554 registry pair contract + ffe234ac gate | T2 |

## Landed in this batch (E45)

### `dynamic_object_type_codes.{h,cpp}` (T1)

The pinned type table (13 types), the >= 0x41 gate, the three per-body skip
sets ({0x16,0x1d}, {0x2e,0x18}, {0xe}), the four family-index gates (11/8/9/4),
the ffffe54c slice offsets (+0xa8/+0x180/+0x1d4/+0x1e0/+0x21c/+0x270/+0xcc)
with the ridable probe order, and `worldPosToMacro` (trunc-toward-zero /32,
matching `__aeabi_idiv`). Tests: `tools/test_dynamic_object_type_codes.cpp`
(exact values, gate boundaries, skip sets, family gates, slice offsets, macro
conversion on the signs of E22/E23's cases). O0/O2 green.

### `object_registry_pair.{h,cpp}` (T2)

The ffffe550 (`dynamicObjectsToAdd`, uniqueID face) + ffffe554
(`dynamicObjectsByWorldPosIndex`, world-index face) bookkeeping contract:
type-gated registration writing both faces, the two lookup faces, and the
ffe234ac loaded-gate resolution (`resolvedByWorldIndex`). Tests:
`tools/test_object_registry_pair.cpp` — registration round trip on both
faces, the >= 0x41 refusal, gate + unloaded behaviour, missing keys and the
operator[]-overwrite re-registration. O0/O2 green.

Fidelity error caught by the tests (recorded because the class will recur):
the first `markUnloaded` implementation updated only the uniqueID face; the
world-index face held a copy and kept resolving. The original keeps one
object with one gate; the slice now keeps both faces in sync and documents
that the gate belongs to the object.

Boundaries: the slice abstracts the per-type 65-segment indexing into a flat
type dimension; registration/loader call sites and the ffe232a0 flag-1 call
are not modelled; no runtime-equivalence claim (no differential oracle).

## Landed in batch E46

### `dynamic_world_changed.{h,cpp}` (T2)

The ffffe578 recorder contract: the producer face
(`dynamicWorldChangedAtPos:objectType:`, E30 0x008e1390) with its skip set
{0x16,0x1d}, the type gate (>= 0x41), the /32 macro conversion and the
**65-segment exact-pair dedup** (segment count from E29's destructor loop,
0x30c/12); and the consumer idioms (E40 saveDynamicObjects): the
`(end - start) / 8` pair-count, the per-type skip triple {0x2e,0x18} exposed
as a predicate. Tests: `tools/test_dynamic_world_changed.cpp` (skip set, type
gate, dedup across world positions mapping to the same macro pair, cross-
segment non-dedup, the /8 idiom and the macro helper on negative signs).
O0/O2 green.

Boundaries: the 12-byte segment triple collapses to the observable dedup
behaviour; the segment-addressing choice (`type % 65`) is a stable
bookkeeping device, NOT the original mapping (which is opaque in the
evidence) - callers must use `segmentAt(index)` and not depend on
`segmentForType`; the consumer's client-side condition is caller-owned.

Test-side note: the first test revision asserted the dedup case as a
successful record (the recorder returns false on a dedup hit) - fixed as a
test-expectation bug, not an implementation change.

## Landed in batch E47

### `accessor_triplets.{h,cpp}` (T1/T2)

The typed-accessor triplet dispatcher: the shared family cells (ffe235f0
lookup / ffe23624 add / ffe23600 remove gate) and the **pinned per-type
remove-cell table** (torch ffe23564, ladder ffe23628, egg ffe23618, window
ffe2364c, rail ffe23648, painting ffe23558, column ffe2355c, stairs ffe23560,
motor ffe23640, shaft ffe2362c), with the door (0x14) and workbench (0x2d)
entries carrying the **pos-then-y-1 two-probe** contract (E38/E39) and NO
single-cell remove leg (their removals ride ffe23650/58/6c + ffe233e0/
ffe23690, which are not part of this table). Tests:
`tools/test_accessor_triplets.cpp` — the cell table, the two-probe flag
assignment, the two-probe fall-through (door/workbench hit at y-1; torch
single-probe miss), the add/remove round trip and the per-type remove-cell
return. O0/O2 green (first run).

Boundaries: cell identities are opaque dispatch-slot handles (pinned values
as stable identities); the add-frame payload fields are recorded, not
resolved; door/workbench removal legs are deliberately out of the table.
