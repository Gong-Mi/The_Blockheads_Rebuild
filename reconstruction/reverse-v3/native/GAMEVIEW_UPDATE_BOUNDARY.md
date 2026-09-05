# GameView.update:accurateDT: entry and outgoing boundary

IMP 0x009259c0..0x00928030. All 2460 instruction/literal words are checked
against the pinned original ELF. The complete callsite inventory is now 80:
41 indirect blx and 39 direct bl. The previous 41-only count omitted direct
calls and was NOT the full function denominator. Twelve direct calls target
Objective-C send/stret labels; the other 27 are C/C++/runtime helpers.
Eleven local selector routes are reviewed, while remaining entries retain an
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

The subsequent horizontal-boundary code reads translation and worldWidthMacro;
its local selector routes are recorded, but wrap/clamp writeback behavior is
not yet fully reviewed. Do not assume modifying a returned Vector2 temporary
necessarily updates the world without tracing the consumer/setter.

stret ABI differs from normal send: r0=result buffer, r1=receiver, r2=selector.
These calls were omitted by the previous blx-only inventory and must remain
separate from ordinary r0-receiver/r1-selector analysis.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_gameview_update_boundary.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output "$TMPDIR/gameview-update-boundary.json"
```

Next: horizontal-boundary consumers and remaining input/zoom branches.
Use the full 80-entry inventory; selector-route review is not whole-callee or
whole-branch semantic completion. Do not infer call order from selector refs.
