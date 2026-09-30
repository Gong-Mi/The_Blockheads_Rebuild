# GameView primary/secondary touch callback batch

Original ELF: `libApplication.so` ARM32, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

This batch extends the recovered GameView input path in both directions: original
ARM evidence is converted into a bounded replacement callback contract, while the
replacement runtime gains an explicit input-state boundary that can later be
wired to the recovered callbacks. Scope is static ARM/ObjC evidence; not runtime
behavior verification. It does not claim ObjC/Foundation or Android runtime
equivalence.

static ARM/ObjC evidence; not runtime behavior verification.

## Static method inventory

| Method | ARM interval | Instructions | direct selector refs |
|---|---:|---:|---:|
| startTouch:withTouch:withEvent: | 0x0092be2c..0x0092c148 | 775 | 6 |
| moveTouch: | 0x0092c148..0x0092c3f4 | 171 | 4 |
| endTouch: | 0x0092c3f4..0x0092c638 | 145 | 4 |
| cancelTouch: | 0x0092c638..0x0092c89c | 153 | 4 |
| startSecondaryTouch:withTouch:withEvent: | 0x0092c89c..0x0092cba8 | 195 | 7 |
| moveSecondaryTouch: | 0x0092cba8..0x0092cdd8 | 140 | 5 |
| endSecondaryTouch: | 0x0092cdd8..0x0092cfa0 | 113 | 4 |
| cancelSecondaryTouch: | 0x0092cfa0..0x0092d188 | 122 | 3 |

Counts are bounded ARM words between the method IMP and the next ARM.exidx
function boundary. Pool words at the end of each interval are not instructions.

## Confirmed common gate

All eight callbacks first inspect the per-touch active byte at the receiver
field selected by the method's PIC/ivar chain. A zero active byte reaches the
common return/cleanup block. The callbacks then test `isSimulating` and
`loadComplete`; the exact short-circuit order and field offsets remain
receiver/selector dataflow work, not a name-based claim.

## Primary touch path

`startTouch:withTouch:withEvent:` stores the CGPoint and touch/event objects in
its frame, clears the primary active/index-related bytes, then follows the
UI gate. Selector references prove `uiManager`, `touchIsInUI:`, `tapCount`,
`startTouch:tapCount:` and `startTouch:tapCount:index:`. The two latter calls
are indirect/dynamic receiver paths in the current static extraction; do not
assign them a concrete UI or gesture implementation yet.

`moveTouch:` and `endTouch:` reference the primary direct callback selectors
`moveTouch:` / `endTouch:` plus indexed `moveTouch:index:` / `endTouch:index:`.
`cancelTouch:` references `endTouch:` and `cancelTouch:index:`. The static
shape supports a primary callback forwarding chain, but selector occurrence is
not an execution-order proof where Objective-C dispatch is indirect.

## Secondary touch path

`startSecondaryTouch:withTouch:withEvent:` has the same UI/tap gate shape but
calls `startTouch:tapCount:index:` and checks `currentTouchIsInAnyButtons`.
The indexed path is separate from primary `startTouch:tapCount:`.

`moveSecondaryTouch:` references `moveTouch:index:`, `endTouch:index:` and
`cancelTouch:index:`. `endSecondaryTouch:` references `endTouch:index:` and
`cancelTouch:index:`. `cancelSecondaryTouch:` references `cancelTouch:index:`.
The current evidence proves the indexed forwarding family, not the dynamic
index value or the concrete touch object lifetime.

## Replacement-side contract

The replacement APK now has an independent direct input state:

```text
GameActivity move buttons
→ handleMoveNative(axis,jump)
→ Player.inputAxis / jumpRequested
→ EntityManager::update
→ Player::update physics tick
```

This is intentionally not labelled as the original GameView callback
implementation. The contract exists so the replacement can be exercised while
these original callback bodies are progressively translated. The movement
behavior test is `gameplay_movement`; the full replacement gameplay suite is
run through `tools/gameplay/CMakeLists.txt`.

## Evidence and boundaries

- Original ARM evidence is in the external reproducibility directory
  `$HOME/blockheads-work/gameview-touch-disasm/` and selector TSVs in
  `$HOME/blockheads-work/gameview-touch-refs/`; the original ELF is not stored
  in the repository.
- `disassemble_objc_methods.py` emitted r2's expected shared-object entrypoint
  warning but used each explicit IMP and ARM.exidx end. This is not a failure of
  the bounded method extraction.
- No selector/receiver route is promoted to behavior-verified solely from these
  counts. `uiManager`, touch UI classification, tap count, indexed callback
  receiver, and input/window coordinate units remain explicit dependencies.
- No Android foreground, original app runtime, or device differential was run.
