# World.setTranslation: complete local-method recovery

## Scope and status

`world_translation.{h,cpp}` implements the complete bounded local setter body, not a plain field assignment. This is a standalone logical-source slice, **not integrated into FrameWorld/the game**, and **not original-runtime equivalence**. The source is now included in `blockheads_recovered_view`, CTest and the explicit method manifest. `WorldTranslationState` extends the existing getter state so both slices share `accurateTranslation` and width without duplicated storage; a concrete FrameWorld adapter is still required.

Source ELF SHA-256: `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.
Setter code `[0x005531d0,0x0055365c)`, pool/padding through `0x005536a4`. Region SHA-256 `a587b51ed92d57877723438e5518d8a149f84c1df11468b61b0b8a380279a9e1`. Full pinned instructions remain in `disasm_world_view_contracts.txt`; its older NOT IMPLEMENTED label is superseded by this slice, not edited here.

`recover_world_translation.py` verifies all 291 instruction words via the complete-region hash; enumerates all 18 direct calls and 8 branches; checks field relocation chains, selector strings, classref, method metadata ABI, both PLT import routes, complete identity helper body and numeric constants. JSON gives per-call receiver roles and per-branch semantics. Word coverage is not runtime verification.

## Complete behavior

1. Entry ABI: r0=self, r1=setTranslation:, r2/r3=the two raw float words of by-value Vector2. Copy both to `accurateTranslation` (offset 0x270).
2. Width is **32-bit wrapping LSL #5, then signed-int32 to float32** of `worldWidthMacro` (0x0c). Not signed C++ shift, unsigned float conversion, double multiplication, nor the getter's load+DMB sequence.
3. If x is ordered >= width, subtract width **once**, then independently subtract width from `translationGoal.x` (0x278) only if goal.x is ordered >= width. Else if x < 0, add width once; adjust goal.x only if goal.x < 0. No loop/modulo; y values untouched. NaN follows the original VFP flags: BLT includes unordered, BPL includes unordered. C++ ordered comparisons express the resulting complete branch paths.
4. Snapshot double `pinchScale` (0x190). Clamp this **local** to 1 only on ordered `< 1`; retain NaN. VFP immediate words encode actual 1.0. Pool f64 at 0x553660 is 40.0.
5. For x then y, compute float32 quantum as `float(1.0 / (40.0 / localScale))`, with **two double divisions then narrowing**. Call imported `__wrap_fmodf` on the **original unwrapped by-value argument** and quantum; subtract its float return from the saved original float coordinate. Store x then y into `roundedTranslation` (0x268). Do not substitute wrapped coordinates, floor, integer truncation, or scale/40 algebraic simplification.
6. Send `[MJSoundManager instance]` at 0x5535f4, with classref 0xe89fe0; selector ref 0xe7dd98. It may mutate world state. Only **after it returns**, reload accurateTranslation and double pinchScale, narrow the latter to float (without clamp), then send `[returnedInstance setListenerPosition:position zoom:zoom]` at 0x553650. r0=returned receiver, r1=selector at ref 0xe7dd9c, r2/r3=Vector2, stack[0]=float zoom. Listener metadata ABI is `v20@0:4{Vector2=[2f]}8f16`. Nil receiver suppresses the effect but does not suppress the preceding math or instance call.

## Dependencies and honest boundaries

- `Vector2::operator float*()` at 0x4bdaac is fully recovered: five instructions, returns this unchanged. Inlined field/local access is the complete helper behavior, not a stub.
- PLT 0x1c3d4c resolves through relocation 0x1060228 to **undefined imported `__wrap_fmodf`**, not an in-ELF arithmetic implementation. Production requires `WorldTranslationRuntime::wrapFmodf`; tests provide `std::fmod` explicitly as a test boundary, not as proof of the original wrapper's exceptional-value/FP-environment semantics.
- PLT 0x1c281c resolves to objc_msgSend. Class and selectors are proven; dynamic instance/listener callee bodies are **not recovered in this batch**. Mandatory pure-virtual interfaces expose both dispatches instead of silently omitting them. Original Objective-C receiver identity, substitute instances, exception behavior and audio engine internals remain outside acceptance.
- Portable C++ models value/state/order under ordinary floating-point operation. Original FPSCR exception flags, DN/FZ/subnormal configuration, NaN payload propagation and ARM memory concurrency are not verified. No original runtime executed.

## Executed acceptance

A compileable **test-only assignment negative control** failed at the first width-wrap assertion (exit 134). It is guarded by `TRANSLATION_ASSIGNMENT_NEGATIVE_CONTROL` in the test, never in production. Full implementation then passed both O0 and O2 with `-fno-fast-math -ffp-contract=off`.

Tests exercise exact/adjacent width, zero and negative zero, values beyond multiple world widths (single-step behavior), independently gated goals, original-input quantization, signed wrap-before-float conversion (including high-bit and discarded-bit widths), scale clamp, NaN/infinity, nil dispatch, ordered outgoing calls, world mutation during imported math, and post-instance reloading of translation/scale. A test expectation originally assumed 32.5 is exactly on a 0.05f grid; actual fmod exposed float divisor representation and the assertion was corrected to the explicit float expression, not the production arithmetic.

Reproduce from repository root:

```sh
mkdir -p build/world-translation
for opt in 0 2; do
  clang++ -std=c++17 -O$opt -fno-fast-math -ffp-contract=off \
    -Ireconstruction/recovered tools/test_world_translation.cpp \
    reconstruction/recovered/world_translation.cpp \
    -o build/world-translation/test-O$opt && build/world-translation/test-O$opt || exit
done
python tools/recover_world_translation.py --elf ~/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so --check
```

Parent integration acceptance: O0/O2 Release (`-DNDEBUG`) CTest each 4/4 PASS; O1 UBSan trap CTest 4/4 PASS. Regenerated evidence matches the pinned ELF. Ledger: 10478 indexed, 9 implemented, 0 original-runtime behavior-verified. The inherited JSON was stale only in the 14 identity-helper receiver descriptions; it was regenerated from the latest extractor.

The parent reproduced a test-harness defect: with `-DNDEBUG`, the assignment-only negative control incorrectly passed because assertions were removed. The test now undefines NDEBUG before headers; the same Release negative control aborts at the width-wrap assertion (SIGABRT), and CI explicitly checks this rejection before running the real library tests.

Exact-head CI: pending push/verification. Device/audio/original-runtime acceptance: NOT RUN. No Frida or device foreground operations changed.
