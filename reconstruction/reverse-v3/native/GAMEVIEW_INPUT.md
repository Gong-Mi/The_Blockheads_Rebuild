# GameView complete input producer batch

Original ELF SHA256: `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## Complete function map

| Method | Code interval, exclusive end | Instructions | Calls |
|---|---|---:|---:|
| pinchGesture:velocity:state:center:numberOfTouches: | 0x0092d1c4..0x0092dddc | 772 (excludes two inline data words) | 28 |
| pinchZoomToScale: | 0x00940f24..0x00940f84 | 24 | 0 |
| shouldAllowDoubleTap | 0x00940f90..0x00940fe8 | 22 | 0 |

The gesture has 30 branch/join entries (20 conditional plus 10 unconditional); the small double-tap method's inventory includes BX LR as a return, not another conditional branch. Pools end at 0x92de5c/0x940f90/0x940ff0. ARM.exidx boundaries, symbol metadata and instruction words are pinned. `gameview_input_evidence.py` decodes PIC field/selector chains, VFP immediate bits, and PLT imports independently of disassembler labels. All gesture calls and branches have explicit reviewed routes in JSON, not merely a raw address count. Helper assembly covers Vector2 construction, identity, per-lane multiplication/division/addition/subtraction. No reciprocal replacement for the division helper.

## Recovered behavior

- pinchZoomToScale ignores the by-value float after spilling it. It writes pinchZooming=true then hasPinchVelocity=false. It does not set pinchScale and does not notify projection.
- shouldAllowDoubleTap is ordered double pinchScale > 3.0; equal and NaN return false.
- Every gesture clears pinchZooming BEFORE loadComplete/UI-button/simulation/allowsPanning entry gates. World receivers are reloaded across callbacks; nil messages follow their original zero-return behavior.
- After gates, setTranslatingToGoal(false) occurs before state dispatch, including otherwise unhandled state values.
- State 1: conditional startPinchOrPan and translationOffset reset; center minus window lanes 2/3 then y negation; float pinchStartScale snapshot, zero velocity/offset, last factor; float division promoted to double. Apply upper cap, compute pinchStartOffset with pre-photo-floor scale, then photo floor. Notify pinchScaleChanged and only then write pinching=true.
- State 2: factor/scale write, photo floor, notify BEFORE upper cap/velocity gate. Reload state/window after notification. Only ordered finite velocity strictly inside (-100,100), with the original scale gates, updates velocity and hasPinchVelocity; rejection preserves both old fields. NaN scale follows negated comparison branch semantics. Above cap retains old pinchOffset and has no second notification. Otherwise recompute offset from direct lane division, subtraction, float 0.025 multiplication and zero-vector subtraction. Add translationOffset only while scrolling, then dispatch **self.updateTranslation:**, not World.setTranslation.
- States 3/4 clear pinching; other states leave it. numberOfTouches is write-only in this bounded body.
- Both photo-floor sites preserve the pre-callback double scale snapshot, rather than accepting mutations made by takingPhoto. This differs deliberately from the notification sites that subsequently reread fields.

## Executable module boundary

`gameview_input.cpp/.h` uses the same `GameViewState` as updateGameView. `GameViewInputState` contains only the three additional vector ivars, paired with the owner; it does not duplicate shared scale/flags. The module test invokes gesture then the recovered update method, and its notification calls the recovered projection implementation.

Mandatory external calls remain interfaces: uiManager/currentTouchIsInAnyButtons, allowsPanning, setTranslatingToGoal, startPinchOrPan and GameView.updateTranslation. These callee bodies are NOT declared recovered. Existing FrameWorld methods and platform float classification also define acceptance boundaries. `std::isnan/isfinite` models classification, not imported implementation/FPSCR exception identity.

This is single-owner synchronous callback execution, not an ObjC memory overlay. Input/window producers, primary/secondary touch callbacks, init/window sizing, World.update and Android gesture-to-frame plumbing remain unfinished. No original/runtime differential, Android foreground or device gameplay test was run. Method manifest: 15 implemented, zero original-runtime behavior-verified.

## Verification and reproduction

The worker timed out after writing implementation/evidence/tests; timeout is not acceptance. Parent rebuilt CURRENT files and verified:
- O0/O2 Release CTest each 6/6; O1 UBSan trap 6/6.
- Independent test script O0/O2 and four mutations: double-tap equality, cancelled gesture, offset multiplier, inclusive velocity bound. All mutants rejected at behavioral assertions. These are sensitivity checks, not a fabricated historical test-first claim.
- NDEBUG without explicit -UNDEBUG fails compilation with a deliberate test guard. CMake applies -UNDEBUG to the input test only; library retains Release configuration.
- Original-ELF regeneration `--check` matches all existing evidence files. Independent read-only review of the full three-method source and assembly found no confirmed semantic recovery error, including NaN paths, callback rereads, photo snapshots, cap/notification order and the self.updateTranslation receiver. The generator's `--output-dir` permits isolated regeneration. Test result logs go to an explicit optional path, not the tracked source tree.

```sh
python tools/gameview_input_evidence.py "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
python tools/gameview_input_test.py --results "$HOME/blockheads-work/gameview-input-acceptance.json"
for opt in 0 2; do
  cmake -S reconstruction/recovered -B "build/input-O$opt" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE="-O$opt -DNDEBUG"
  cmake --build "build/input-O$opt" --parallel 2
  ctest --test-dir "build/input-O$opt" --output-on-failure
 done
```

Exact-head Android CI is separately reported on canonical PR #1 after logs are checked; local source tests and hash-pinned static evidence do not establish device or original-runtime equivalence.
