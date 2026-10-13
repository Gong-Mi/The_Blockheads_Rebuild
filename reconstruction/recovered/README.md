# Recovered C++ numerical slices

scroll_inertia.h/.cpp is reconstructed C++ source for the confirmed inertia
numerical/state slice, not a source dump or full GameView implementation.
It is intentionally not wired into app runtime: world getter/setter ordering,
receiver identity, complete input lifecycle and nil/callee behavior must be
established before integration. A caller receives an explicit writeTranslation
flag rather than silently changing world state.

Evidence: GAMEVIEW_UPDATE_BOUNDARY.md and disasm_vector2_inertia_helpers.txt.
The finite-input arithmetic order mirrors original float/double instructions;
compile without fast-math and with -ffp-contract=off. NaN, infinities, FP exception
flags, subnormal/FTZ modes, and runtime equivalence are NOT validated.

The numerical tests cover manual-input priority, goal cancellation, damping,
squared-speed stop, no invented damping clamp and no invented horizontal wrap.
RED was observed with a placeholder result (FAIL: inertia requests setter), then
real implementation passed local O0 and O2 builds. CI builds/runs both variants.

```sh
c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off \
  -Ireconstruction/recovered tools/test_scroll_inertia.cpp \
  reconstruction/recovered/scroll_inertia.cpp -o "$TMPDIR/test_scroll_inertia"
"$TMPDIR/test_scroll_inertia"
```

This is actual compiled recovered logic, but its tests use controlled inputs,
not an original-runtime differential oracle. Do not label this game integration
or complete original-source recovery.

## World-line slice index (E45–E61)

The reverse-v3 world-line equivalence line (see WORLD_LINE_EQUIV_PLAN.md for
the batch mapping and T1–T4 grading rules). Each slice: one static-library
translation unit + a `tools/test_*.cpp` contract test, built by the CI
`recovered` lane at O0 and O2 with
`-Wall -Wextra -Werror -ffp-contract=off`.

| slice | grade | evidence | contract |
|---|---|---|---|
| `world_change_queues` | T2 | E21/E22/E23 | queue producers + flush passes (first slice) |
| `dynamic_object_type_codes` | T1 | E24–E44 | type table, >=0x41 gate, skip sets, family gates, fffe54c slices, /32 helper |
| `object_registry_pair` | T2 | E26/E30/E31/E33/E40 | ffffe550/ffffe554 dual-face registry + ffe234ac gate |
| `dynamic_world_changed` | T2 | E29/E30/E40 | ffffe578 recorder (skip set, /32, 65-segment dedup) + (end-start)/8 |
| `accessor_triplets` | T1/T2 | E36–E39/E43 | per-type remove-cell table + door/workbench pos-then-y-1 |
| `world_collections` | T2 | E27/E29/E31/E35/E40/E42 | ffffe4f0/4f4/4f8 merges + client/server booleans |
| `simulation_step` | T2 | E40 | dt/8.0f x 8 families, accurate update, 8-slot finisher |
| `tree_life_fraction` | T2 | E23 | tent kernel (|d|/32), 2^31 gate, weight/32 |
| `door_state` | T2 | E38/E39 | 0x34/0xa4 -> 0x46 marker gate, open/direction state |
| `client_registry` | T2 | E30/E33/E39 | server gate, selector quintet, pole dict, workbench flag |
| `light_channels` | T2 | E28/E29/E31/E42 | 32-slot ffffe56c array, -1 all-channels arm |
| `save_sweep` | T2 | E22/E40 | five-container scan order 570/574/578/57c/580 |
| `blockhead_selection` | T2 | E42 | ffffe55c slot, 0-on-out-of-range, resolver nil path |
| `family_probes` | T2 | E32/E34/E38/E39/E43 | indexed arm probe + sequential loop probe |
| `interaction_objects` | T2 | E39 | uint16 type query + shared ffe23690 removers |
| `sound_accumulator` | T2 | E24/E42/E43 | ffffe5a4 >= 1.0 gate + play callback |
| `net_sync_phases` | T3 | E21/E32/E40 | four phases + drains + receiver gates |
| `bucket_arrays` | T2 | E32/E40 | ffffe544/ffffe53c lazy create-on-null arrays |
| `tile_markers` | T1 | E30/E38 | 0x46/0x4b arm-1, 0x45 arm-2, strict > 0xaa threshold |

Standing boundaries (apply to every slice): A/B evidence defines the
contract; D hypotheses stay isolated; cell identities are opaque handles
unless a name is symbol-table-derived; slice offsets are offset-pinned;
no runtime-equivalence claim without a differential oracle.
