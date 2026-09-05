# GameView.update:accurateDT: entry and outgoing boundary

IMP 0x009259c0..0x00928030. All 2460 instruction/literal words are checked
against the pinned original ELF. 41 indirect call sites are enumerated in JSON;
only THREE selector call sites are reviewed in this slice. The other 38 remain
explicitly indexed-only. This is not full update/camera/input semantic recovery.

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

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_gameview_update_boundary.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output "$TMPDIR/gameview-update-boundary.json"
```

Next: middle region 0x00925c6c..0x00927ed8 input/camera branches and remaining
callsite records (the 38 pending entries also include the two defaults calls in
the entry timer block). Do not infer call order from selector refs.
