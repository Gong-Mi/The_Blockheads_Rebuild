# GameView complete method batch

## Deliverable, not five independent snapshots

`reconstruction/recovered/CMakeLists.txt` builds the static target
`blockheads_recovered_view`. Its public entry point is:

```cpp
updateGameView(GameViewState&, FrameRuntime&, float dt, float accurateDT);
```

It executes the entire logical `GameView.update:accurateDT:` control flow,
including real interface calls to World/defaults, not a precomputed effect list.
The default `FrameRuntime::pinchScaleChanged` executes the recovered matrix
helper and writes all 16 projection floats and cameraZ into the same mutable
GameViewState. The separate snapshot helpers remain independently tested;
only callback-free numerical phases are reused in the full method.

This is a working method/dependency module, NOT yet an adapter into the existing
Android game's frame loop. FrameWorld/FrameDefaults implementations in the
method test are controlled dependencies. They are not a reconstructed World,
original database, or Android preferences implementation.

## Complete original ownership

Original ELF SHA256:
733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7.

`gameview_method.json` maps every original update word range and all 80 calls to
source owners/bindings: 53 Objective-C calls and 27 C/C++ helper calls. There are
no remaining unclassified update callsites. This mapping is ownership evidence,
not a claim that every downstream World method has been reimplemented.

| Original range (end exclusive) | Compiled owner |
|---|---|
| 0x9259c0..0x925c6c | updateGameView: entry/time/mode |
| 0x925c6c..0x926278 | scroll: inertia and repeated horizontal queries |
| 0x926278..0x9263e0 | pinch + stepPinchReturn |
| 0x9263e0..0x9266d0 | pinch: staged inertia and photo query |
| 0x9266d0..0x926a4c | returnTranslation + numerical return |
| 0x926a4c..0x926acc | updateGameView: initial maxScale |
| 0x926acc..0x927ed8 | settle + numerical table + real callbacks |
| 0x927ed8..0x928030 | updateGameView: forwarding/return and pool |

Update: 2460 checked words. Projection callback and complete matrix helper:
216 checked words, with exact field/constant/storage evidence in
`projection_update.json` and `PROJECTION_UPDATE.md`.

## Boundaries that full-method execution now preserves

- Rendered-frame gate precedes time accounting. Time adds accurateDT, tests
  strictly greater than10, increments total by10 ONCE, obtains defaults,
  rereads total for setDouble, then rereads/subtracts timeCounter. fmodf uses
  the post-callback total converted to float, divisor3600. The converging
  fmod-result and matchMaker flag branches do not gate the remainder.
- loadComplete and isSimulating separately reload world. Simulating skips
  camera logic, not the final World.update call. Nil loadComplete returns false.
- The outer scrolling/pinching gate is selected once. Callbacks changing those
  flags do not retroactively skip already-selected pinch/vertical work.
- Scroll stores decayed velocity BEFORE getting translation, then rereads
  velocity AFTER that getter. Its setter receiver was captured BEFORE the
  getter. Later horizontal getters reload world and remain observable even
  when the local wrap edits are ultimately discarded.
- Width conversion implements ARM's low32-bit left shift followed by signed32
  float conversion, not C++ signed-shift UB. Right-boundary BLT skips both
  less-than and unordered (VFP unordered NZCV=0011, N!=V); its fallthrough is
  ordered >=. A dedicated NaN query-count regression corrected an initially
  wrong negated-less-than translation. This is not full FPSCR parity.
- Pinch return consumes its branch even if defaults callbacks change flags;
  it does not fall through to pinch inertia. Defaults providers can change the
  scale that is subsequently read and persisted.
- Pinch inertia writes the ratio before takingPhoto, but preserves that ratio
  across the query and overwrites any query scale mutation with the clamped
  cached ratio. Other query field mutations remain intact. Then notification
  executes the real default projection/camera calculation.
- Vertical return reads bounds after translation getter and reloads the
  setter receiver, unlike the scroll setter's captured receiver. maxScale is
  computed after this setter from the then-current window lane1.
- Post-cap zoom has ordered gates. The selected numeric phase does not repeat
  already-tested camera/pinching gates after the photo query. Snap writes are
  followed by defaults lookup, a fresh scale read, persistence and notification.
  The tail reloads hasPinchVelocity, lastPinchFactor and scale after callbacks.
- Final World receiver, scale and drag flags are fresh. Original dt and
  accurateDT remain distinct float parameters; drag excludes inertia flags.

## Executed tests and scope

`test_gameview_update.cpp` invokes the complete entry point with dependencies
that synchronously mutate world identity, velocities, scales, flags, dimensions
and time fields. It checks query/setter order, counts, branch consumption,
nil receivers/defaults, single-interval accounting, pre-query scale visibility,
cached ratio overwrite, post-callback persistence/tail and real projection
field writes. Release builds explicitly keep assertions enabled.

`test_projection_update.cpp` exercises the full recovered matrix arithmetic,
including exact storage order and exceptional/rounding cases. Its host reference
is not original ARM execution; tanf's last-bit cross-platform behavior, FPSCR
modes, signaling NaNs, errno and exception flags remain unverified.

Both executable test suites pass locally at O0 and O2, through the actual static
library target. Prior scalar and byte-evidence suites remain separate regression
layers. Original-runtime differential and Android gameplay integration have
NOT been performed.

Supported method model is single-threaded, with synchronous callback mutation
and adapter-owned borrowed object lifetimes. It is not the original ARMv7 ObjC
layout/ABI. Concurrent mutation, object destruction during a captured call,
platform hook interposition and full fenv equivalence are outside this model.

The ledger accepts explicit source/test/evidence records for the two original
GameView methods, preserving their scopes. It does NOT infer implementation
from names, nor mark original-runtime behavior-verified from these local tests.
The C++ matrix helper is a direct dependency, not an extra ObjC-method count.

## Reproduce

```sh
export PYTHONDONTWRITEBYTECODE=1
python3 tools/recover_gameview_method.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output "$TMPDIR/gameview-method.json"
cmp "$TMPDIR/gameview-method.json" reconstruction/reverse-v3/native/gameview_method.json
python3 tools/test_gameview_method_map.py
for opt in 0 2; do
  build="$TMPDIR/blockheads-methods-O${opt}"
  cmake -S reconstruction/recovered -B "$build" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE="-O${opt} -DNDEBUG"
  cmake --build "$build" --parallel 2
  ctest --test-dir "$build" --output-on-failure --verbose
done
```

Next batch: recover/close the World-side translation/update contracts and the
input/window-state construction needed for a real game adapter. Do not replace
that work by linking the library into the APK without a verified call path.
