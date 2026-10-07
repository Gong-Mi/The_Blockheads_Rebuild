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

## Landed in batch E48

### `world_collections.{h,cpp}` (T2)

The blockhead-collection members and merge getters: the trio ffffe4f0
(local) / ffffe4f4 (net) / ffffe4f8 (blockheads), the client/server slot
booleans (ffffe518 / ffffe51c != nil; ffffe514 serverClients via the E40
setter), `netBlockheads` = merge(local, net), `allBlockheadsIncludingNet` =
merge(local, net, blockheads) and `localAndDisconnectedClientBlockheads` =
client -> blockheads directly, server -> merge(local, blockheads). Tests:
`tools/test_world_collections.cpp` — booleans, the three merges, the branch
split and duplicate preservation (no dedup evidence). O0/O2 green (first
run).

Boundaries: collections are ordered id lists (container classes not
modelled); the server-side merge call handles (ffe23204/ffe236a8) are opaque;
merge duplication is preserved because no dedup evidence exists.

## Landed in batch E49

### `simulation_step.{h,cpp}` (T2)

The simulation-step family: `simulate:`'s **dt / 8.0f** family step over the
**8 families** (E40 0x008c9740; the divisor pinned as the exact 8.0f literal,
bit-checked), `update:accurateDT:`'s single-call both-floats contract
(0x008c9810) and `finishSimulating`'s **8-slot inner loop** per ffffe4f8
blockhead (0x008cbc8c). Tests: `tools/test_simulation_step.cpp` — the divisor
bit pattern (0x41000000), family visitation order + divided dt, the
one-call accurate variant and the finisher slot counts (3x8, zero case).
O0/O2 green (first run).

Boundaries: ffe234e8/ffe234f8 are callbacks; the sxtb flag's origin is
caller-provided (not established in the batch); slot semantics opaque.

## Landed in batch E50

### `tree_life_fraction.{h,cpp}` (T2 numeric kernel)

The density kernel of `getTreeLifeFractionForPos:` (E23 0x008f9b70, 1160
words, fully read in the batch): the **bilinear tent** max(0, 1 - |d| / 32)
per axis with the **decay divisor 32.0** (bit-checked 0x42000000), the
**2^31 random gate** predicate (< 0x80000000 passes), the per-tile product
`tileContribution` and the `(weight / 32)` normalised `weightedTerm` in the
ffe236fc domain. Tests: `tools/test_tree_life_fraction.cpp` — divisor bits,
gate boundaries (0x7fffffff / 0x80000000), tent values incl. symmetry and
clamping, product separability and the normalisation cases. O0/O2 green
(first run).

Boundaries: the radius ladder (2.0, x5, 10/50/250) is recorded as constants
but not wired; the per-class weight table (0xE4AA60, 11 classes) stays
opaque; the field summation is caller-side.

## Landed in batch E51

### `door_state.{h,cpp}` (T2)

The door state family (E38/E39): the **marker-write gate** (tile byte 0x34
'4' or 0xa4 -> write the 0x46 'F' marker, with the neighbour re-read as a
callback), the **open/direction state** (ffe23650 fetch / ffe23658 check /
ffe2366c set-fetch cells; missing keys read closed per the check path's
0-store), and the usage/removal cell identities (ffe23654 / ffe232b0 /
ffe23690). Tests: `tools/test_door_state.cpp` — the marker gate on all byte
classes, the re-read callback gating, the open/direction round trip and
multi-door independence. O0/O2 green (first run).

Boundaries: cells are opaque handles; the direction domain stays "an sxtb'd
byte"; doorAtPos's y-1 probe lives in `accessor_triplets` and is not
repeated.

## Landed in batch E52

### `client_registry.{h,cpp}` (T2)

The client registry and flag slots: the ffffe51c server gate on all
users/bans operations, the **selector quintet** (ffe237a8 mute / ffe237ac ban
/ ffe237b0 query / ffe237b4 playersChanged / ffe237b8 owner name; E33), the
+0x270 client-slice offset constant, the **pole-taken dict** (ffffe564 with
the pinned 0xfff34284 key, E30/E23) and the **workbench flag** ffffe558
(E39 getter / E30 writer). Tests: `tools/test_client_registry.cpp` — the
server gate refusals, mute/ban notifications with the exact cells, the ban
query and owner-name accessors, the playersChanged fan-out and the
pole/workbench pairs. O0/O2 green (first run).

Boundaries: selector cells are opaque handles; the dict value domain is not
resolved; the +0x270 slice identity is offset-pinned.

## Landed in batch E53

### `light_channels.{h,cpp}` (T2)

The light-channel array (ffffe56c): the **32-slot** structure (0x180/12 from
E29's destructor loop; the `cmp 0x20` bound in E28's sendLightblocksToClients),
the per-channel changed byte written by E31's exploreLightChangedAtMacroPos:
(including the **-1 all-channels arm**), the 12-byte record stride constant,
the ffe23580 forwarder cell (E42) and the ascending send iteration contract.
Tests: `tools/test_light_channels.cpp` — bounds (32 edges refused), the
all-channels arm, the ascending emission order and clearAll. O0/O2 green
(first run).

Boundaries: only the changed byte of the 12-byte record participates; the
remaining record fields are opaque; the queue feed itself lives in the E23
world_change_queues slice.

## Landed in batch E54

### `save_sweep.{h,cpp}` (T2)

The five-container save sweep of `saveGameWithWorldData:signOwnershipData:`
(E22 0x008b29bc): the pinned scan order **570 (reliable) / 574 (unreliable) /
578 +0x120 slice (dynamicChanged) / 57c (third queue) / 580 (snow)**, the
element walk in insertion order (the (end-start)/8 count) and the per-element
callback contract. Tests: `tools/test_save_sweep.cpp` — the exact container
order, the insertion-order walk, empty-container skipping and the empty
sweep. O0/O2 green (first run).

Boundaries: the +0x120 slice is abstracted into the same container (offset
recorded as a constant); the 57c consumer role stays unestablished (E23);
the save flags remain in the world_change_queues flush contract.

## Landed in batch E55

### `blockhead_selection.{h,cpp}` (T2)

The active-blockhead selection (E42): the **ffffe55c** index slot (default 0),
the range-check-then-store setter (in range -> the index; **out of range -> 0**,
covering index >= count per the bhs boundary) and the resolver's nil path
when the stored index exceeds the collection count (the slot is NOT
rewritten by the resolver). Tests: `tools/test_blockhead_selection.cpp` — the
default slot, in-range stores, the 0-store rule (5 / -1 / index==count) and
the shrink-then-resolve boundary. O0/O2 green (first run).

Boundaries: the ffffe4f8 collection is an ordered id vector; ffe231cc fetch
opaque.

## Landed in batch E56

### `family_probes.{h,cpp}` (T2)

The two family-probe disciplines: the **indexed arm probe** (`arg >= N` gate
-> exactly one table arm -> the arm lookup; miss stays caller-side, as
npcWithID: / interactionObjectWithID:) and the **sequential loop probe**
(ascending arms 0..N-1, first hit wins, exhaustion -> nothing; treeAtPos:'s
`add r0, r0, 1` loop). The pinned arm counts live here as constants (NPC 8 /
interaction 9 / tree 11 / train 4). Tests: `tools/test_family_probes.cpp` —
the counts, the gate refusals probing zero arms, single-arm dispatch, the
first-hit-wins order and exhaustion. O0/O2 green (first run).

Boundaries: arm identities are opaque; the second-registry fallback (ffffe550)
stays out of the probe helpers.

## Landed in batch E57

### `interaction_objects.{h,cpp}` (T2)

The interaction type query (ffe23570 fetch -> the ffe23688 type as
**std::uint16_t** via strh/ldrh; absent -> 0) and the two remover legs
sharing the **ffe23690** removal: the workbench leg's ffe233e0 check and the
interaction leg's ffe23570 fetch, both returning 0 (refusal) on an early hit.
Tests: `tools/test_interaction_objects.cpp` — the type values including the
0xFFFF width, the leg refusals, the shared removal cell and the equality of
both legs' removals. O0/O2 green (first run).

Boundaries: the early-exit refusal shape is preserved as a refusal, not
reinterpreted; cells opaque; the 9-arm lookup stays in family_probes.

## Landed in batch E58

### `sound_accumulator.{h,cpp}` (T2)

The shared ffffe5a4 sound accumulator with its gate: a value **>= 1.0 exits**
(the vcmpe/bpl take at 0x8de6a4; the threshold bit-checked as 0x3f800000) and
below it the play callback runs with the position (the
playTimeCrystalReceivedSoundAtPos: / openElevatorAtPos: player shape).
Tests: `tools/test_sound_accumulator.cpp` — threshold bits, gate boundaries
(0.999 allowed / 1.0 and 1.5 gated), the callback gating with forwarded
positions and the accumulation to exactly 1.0. O0/O2 green (first run).

Boundaries: finite-value domain only (vcmpe NaN/unordered behaviour NOT
modelled - no evidence read); the bump amount stays caller-side; the 0xfff34074
/ 0xfff34174 strings and ffe2af10/ffe232c8/ffe23480 cells are the player's
opaque handles (E24/E42/E43).

## Landed in batch E59

### `net_sync_phases.{h,cpp}` (T3)

The updateNetObjects four-phase contract (E21): phases **A create/remove (65
slots, 8-byte IDs) -> B creation-data (24-byte records) -> C update -> D
remove (needsRemoved)**, each ending with the **removeAllObjects drain**; the
receiver gates as predicates (remoteCreate skips 0xe FreeBlock per E40;
remoteUpdate takes the 0x3c gate per E32). Tests:
`tools/test_net_sync_phases.cpp` — the strides/constants, both gates, the
phase order + per-phase counts, the drain (second pass sends nothing). O0/O2
green (first run).

Boundaries (T3 as the plan graded): the wire marshalling, the 65-slot pair
structure and the receiver buckets are out of scope; the phase queues carry
typed records and a send callback consumes them.

## Landed in batch E60

### `bucket_arrays.{h,cpp}` (T2)

The remote-receive slot arrays: the ffffe544 (creation-data, ffe2aeb0 class)
and ffffe53c (remote-create, ffe2aeb4 class) **4-byte pointer arrays with
lazy create-on-null** semantics, the objectType domain gate [0, 0x41) and the
pre-bucketing predicates (remoteCreate skips 0xe; remoteUpdate takes 0x3c).
Tests: `tools/test_bucket_arrays.cpp` — the gates, lazy create + same-slot
reuse + per-index independence, gate refusals and the two arrays' mutual
independence with their create tags. O0/O2 green (first run).

Evidence correction recorded: E32's remoteUpdate walk reads ffffe51c, which
E33/E35 later PROVED to be the server registry slot (setServer: writes it;
isServer reads its nil-ness) — it is therefore deliberately NOT modelled as a
third bucket array here.

## Landed in batch E61

### `tile_markers.{h,cpp}` (T1)

The tile-marker constants and predicates (E30's background free-block
dispatch; E38's door marker write): arm 1 = {0x46 'F', 0x4b 'K'}, arm 2 =
{0x45 'E'}, the strict **> 0xaa** ore-threshold predicate (equality does not
pass). Tests: `tools/test_tile_markers.cpp` — the values, the arm predicates
including full-byte disjointness and the strict threshold boundaries. O0/O2
green (first run).

Boundaries: marker meanings (which content each byte denotes) unresolved;
affected call sites stay out of scope.
