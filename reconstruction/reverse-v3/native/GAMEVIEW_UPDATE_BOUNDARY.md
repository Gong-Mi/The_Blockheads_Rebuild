# GameView.update:accurateDT: entry and outgoing boundary

IMP 0x009259c0..0x00928030. All 2460 instruction/literal words are checked
against the pinned original ELF. The complete callsite inventory is now 80:
41 indirect blx and 39 direct bl. The previous 41-only count omitted direct
calls and was NOT the full function denominator. Twelve direct calls target
Objective-C send/stret labels; the other 27 are C/C++/runtime helpers.
Nineteen local selector routes are reviewed, while remaining entries retain an
explicit indexed-only status. This is not full update/camera/input recovery.

## Entry

- r2 dt -> fp-0x28; r3 accurateDT -> fp-0x2c (0x009259d4..0x009259f0).
- Read hasRenderedFrameSinceActivate (GameView offset 362). If false, branch
  0x00925a10 goes directly to return 0x00927fd8.
- Add accurateDT to float timeCounter (offset 280).
- Compare against TEN, not one. The checked instruction at 0x00925a18 is
  0xeeb20a04: VFP immediate8=0x24 expands to 10.0. The existing disassembler
  prints `vmov.f32 s0, 1`; that label is not the machine-code value.
- For finite timeCounter > 10, totalGamePlayTimePassed (double, offset 272)
  increments by 10, is passed to defaults setDouble:forKey: using key
  totalGamePlayTimePassed, and timeCounter decreases by 10 once.
  The double increment opcode 0xeeb22b04 also expands to 10.0, not one.
  This is an if branch, not a catch-up while loop. The later fmodf/compare
  fragment has converging branches; no further effect is claimed here.

## World gates (reviewed calls)

- 0x00925c10 sends world.loadComplete. False returns immediately at 0x00927fd8.
- 0x00925c5c sends world.isSimulating. True jumps to 0x00927ed8, bypassing the
  middle input/camera block but NOT skipping the final World update call.
- The earlier matchMakerIsAddingToGame branch converges immediately; its mere
  field reference must not be described as a demonstrated return gate.

## Outgoing World ABI (0x00927ed8..0x00927fd4)

Receiver is self.world, offset 24. Selector at 0x00927fd4 resolves to
update:accurateDT:pinchScale:dragInProgress:.

- r2: dt from original fp-0x28 slot
- r3: accurateDT from original fp-0x2c slot
- stack[0..7]: double self.pinchScale, offset 152
- stack[8]: boolean (scrolling || pinching), offsets 196 and 173

The boolean defaults true; when scrolling is false, it is replaced by normalized
pinching, then narrowed for the call. Both float argument slots are separately
loaded. This slice does not claim the large middle region never modifies them;
that requires the remaining write/dataflow audit.

The reviewed constructor establishes GameView and its world ivar source, not
runtime identity of the world object. Nil dispatch and exceptional/mutated-frame
cases are not runtime-verified.

## Inertia path reviewed (0x00925c6c..0x00925f28)

- scrolling or pinching skips this path to 0x00926a4c.
- hasVelocity (offset 197) false skips to 0x00926278.
- world.translatingToGoal at 0x00925d14 true clears hasVelocity and skips inertia.
- Otherwise scrollVelocity (Vector2 at offset 188) is multiplied by a scalar
  derived from `1.0 - float32(dt * 4.0)`, converted back to float32 for the
  Vector2 scalar multiplication. VFP immediate decoding confirms 4.0.
- If the resulting lengthSquared is below float32(0.1), clear hasVelocity.
  Do not mistake this for speed < 0.1: the comparison uses squared length.
- Otherwise read world.translation via objc_msgSend_stret at 0x00925e7c,
  with an explicit 8-byte zero fallback for nil receiver.
- Compute translation minus (decayed scrollVelocity * dt), then send
  world.setTranslation: at 0x00925f28.

The horizontal-boundary consumers have now been followed through 0x00926278.
Vector2::operator float*() at 0x004bdaac returns its own this pointer unchanged.
The add at 0x00926094 writes into the getter result at fp-0x60; the subtract at
0x00926264 writes into another getter result at fp-0x70. These are local stret
return buffers. No setTranslation: or copy back to world follows either write
before convergence at 0x00926278. Under ordinary return-value semantics these
local modifications do not implement world-coordinate wrap. The recovered C++
therefore does NOT add an imagined modulo/wrap setter. Getter/callee side effects
beyond these ordinary ABI semantics remain a separate runtime boundary.

stret ABI differs from normal send: r0=result buffer, r1=receiver, r2=selector.
These calls were omitted by the previous blx-only inventory and must remain
separate from ordinary r0-receiver/r1-selector analysis.

## Pinch return-to-one branch (0x00926278..0x009263dc)

pinchZooming (offset184) selects this branch before hasPinchVelocity handling.
The existing double pinchScale at offset152 evolves as:
`scale += (1.0 - scale) * double(float32(dt * 8.0))`.
The stop test casts the NEW scale to float, subtracts float 1, takes absolute
value, then compares strictly below the literal float32(0.01) at 0x00926664.

On completion, clear pinchZooming (0x00926388), obtain standardUserDefaults
(0x009263a8), and setFloat(currentScaleFloat, "pinchScale") (0x009263d8).
The scale is NOT snapped to exactly one. The branch then jumps to 0x009266d0;
clearing the flag does not fall into the pinch-velocity branch in the same frame.

Executable numerical/state source: reconstruction/recovered/pinch_return.*.
It emits persistScale/handledBranch explicitly but performs no Android settings
writes and is not integrated into the game loop. RED was observed, O0/O2 pass.
As for inertia, finite normal IEEE inputs/FP-contract-off are the tested boundary,
not runtime differential, NaN/FTZ or full pinch-gesture implementation.

## Pinch inertia (0x009263e0..0x009266d0)

Only considered when pinchZooming was false. hasPinchVelocity(offset172) false
skips it; world.translatingToGoal true clears that flag before arithmetic.
The float pinchVelocity(offset164) becomes
`float(double(v) * (1.0 - double(float(dt*16.0))))`.
If abs(newVelocity) < float(0.01), clear the flag and do not update factor/scale.
Otherwise lastPinchFactor(offset168) += float(newVelocity*dt). If that result
is below float(0.01), clear the flag without dividing.

The ratio uses FLOAT division of pinchStartScale(offset160)/lastPinchFactor,
then widens to double pinchScale(offset152). world.takingPhoto at 0x00926624
selects a minimum of 0.125 versus normal 0.5. These are VFPExpandImm decoded
values (raw text prints misleading 1/5). There is no upper clamp in this slice.
After the minimum clamp the method calls self.pinchScaleChanged at 0x009266bc.
The method does not directly persist a setting here.

reconstruction/recovered/pinch_inertia.* reproduces the finite-input numerical
and flag result with an explicit notifyScaleChanged request. takingPhoto and
goal results are supplied snapshots: actual Objective-C query timing and the
intermediate pre-clamp pinchScale store are not simulated. Therefore this helper
is not a drop-in callback implementation or an original-runtime equivalence claim.
RED was observed; O0/O2 tests cover branch precedence, cancellation, both stop
gates, photo/normal minimum and absence of an invented upper bound.

## Translation return and initial scale cap (0x009266d0..0x00926acc)

The earlier scrolling/pinching gates bypass the translation-return region.
The world.translatingToGoal send at 0x0092670c also skips it on true.
Otherwise world.translation at 0x00926764 returns an 8-byte Vector2 into fp-0x90;
nil world uses explicit memset(0, 8), not an invented world allocation.

GameView.windowInfo is symbol-resolved at offset208. This slice uses float
lanes +12 and +4; their viewport interpretation is deliberately not asserted.
With f32 indicating a float rounding boundary:

- lower = f32(double(f32(windowInfo[3] * f32(0.025))) * pinchScale)
- upper = f32(1024 - lower)
- if y < lower AND y < upper, return toward lower;
- else if y > upper AND y > lower, return toward upper;
- otherwise leave y unchanged, including the middle of an inverted interval.

For either return, delta = f32(y - target), factor = 1 - double(f32(dt * 10)).
Compute double(target) + double(delta) * factor, then add/subtract the double
literal 0.009999999776482582 (exact widened float(0.01)), and finally cast to
float. Lower return snaps if newY > f32(lower - float(0.01)); upper return
snaps if newY < f32(upper + float(0.01)). Both comparisons are strict.
The multiplier's raw VFP bits encode TEN despite the printed operand being 1.
Do not clamp dt or suppress the bias at dt=0.

Unlike the earlier ineffective horizontal-wrap writes, this local result DOES
reach a setter: 0x00926a24..0x00926a40 loads x/y from fp-0x90/-0x8c into r2/r3;
0x00926a44 sends world.setTranslation:. The getter and setter separately reload
self.world; snapshot inputs do not model receiver changes or getter side effects.
The setter is sent even if neither correction branch changed y. Nil receiver
semantics remain the caller's responsibility.

The independent region 0x00926a4c..0x00926acc computes float(40960 / windowInfo[1]),
widens it to double, and stores it only if pinchScale is greater. This region
also runs after the scrolling/pinching/goal bypasses. Later zoom flags can
modify pinchScale again: this is NOT the final per-frame maximum contract.

Executable source: reconstruction/recovered/translation_return.{h,cpp}.
Behavioral RED observed (missing unconditional write request), then O0/O2 PASS.
Finite normal arithmetic with finite intermediate results is the supported
numerical contract; NaN, FTZ, FP exceptions and original-runtime differential
acceptance are not verified. No gameplay wiring was changed.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_gameview_update_boundary.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output "$TMPDIR/gameview-update-boundary.json"
```

Next: 0x00926acc onward zoom flags, gesture/translation dispatch, and remaining input branches.
Use the full 80-entry inventory; selector-route review is not whole-callee or
whole-branch semantic completion. Do not infer call order from selector refs.
