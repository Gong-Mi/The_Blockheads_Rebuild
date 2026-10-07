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
