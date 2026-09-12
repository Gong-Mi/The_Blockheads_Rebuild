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
