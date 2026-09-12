# drawFrame reviewed static semantics

Input is the hash-pinned original 1.7.6 ARMv7 libApplication.so. Reproducer:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_drawframe_slices.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output "$TMPDIR/drawframe-reviewed-slices.json"
```

The tool verifies all 283 instruction/literal words in [0x00781a44,0x00781eb0),
then resolves literals, selrefs, ivar symbols and NSDate class relocation.
Call-to-literal and receiver/spill routes are HAND-REVIEWED bounded slices,
not a new automatic alias analysis. The ordinary intact-frame/call-ABI assumption
is explicit. Generic trace_objc_dispatch still yields 2 candidates, not 11.
No runtime/receiver identity or game equivalence acceptance is claimed.

## Fields

EvolutionViewController native ivar byte offsets:

- openGLInitialized: 20
- lastTime: 24 (double access)
- gameView: 32
- isActive: 40
- tempBackgroundView: 44
- frameHasBeenDrawnSinceActivate: 48

## Ordered local path

| call | receiver source | selector | branch/argument |
|---|---|---|---|
| 0x00781b28 | self.tempBackgroundView | removeFromSuperview | if first frame since activation |
| 0x00781b4c | self.tempBackgroundView | release | same path, followed by ivar zeroing |
| 0x00781bc4 | self | view | result becomes next receiver |
| 0x00781bd4 | preceding view result | setFramebuffer | not self.gameView by assumption |
| 0x00781c40 | self.gameView | initOpenGL | only when openGLInitialized is zero |
| 0x00781c98 | NSDate class | timeIntervalSinceReferenceDate | returns double via r0/r1 |
| 0x00781db0 | self.gameView | preUpdate: | r2 from fp-0x2c |
| 0x00781de4 | self.gameView | update:accurateDT: | BOTH r2/r3 from fp-0x30 |
| 0x00781e10 | self.gameView | render: | r2 from fp-0x30 |
| 0x00781e3c | self | view | result becomes next receiver |
| 0x00781e4c | preceding view result | presentFramebuffer | return value only spilled before exit |

`self.view` and `self.gameView` are distinct source paths. This does not prove
they are different runtime objects, but a reconstruction must not conflate them
merely because both names mention view.

## Gates and time flow

- 0x00781a74..0x00781aac: return if !isActive or gameView == nil.
- 0x00781ac8..0x00781b64: if frameHasBeenDrawnSinceActivate == 0, send temporary
  background removal/release then clear the ivar. No extra nonnil check is present.
- 0x00781ba8: set frameHasBeenDrawnSinceActivate = 1 before obtaining framebuffer.
- 0x00781be8..0x00781c58: when openGLInitialized == 0, call gameView.initOpenGL,
  then set the byte flag to 1 after return (not a checked success-result branch).
- 0x00781c98..0x00781cc0: now = NSDate time; subtract lastTime in double,
  convert the difference to float32 at fp-0x2c.
- fp-0x30 is a separate copy, capped above at the float32 literal 0x3dcccccd
  (0.10000000149011612). For a negative difference both copies are replaced by 0.
- preUpdate: reads fp-0x2c; update:accurateDT: reads fp-0x30 twice;
  render: reads fp-0x30 once.
- 0x00781e14..0x00781e28: lastTime = sampled now, AFTER render and before present.

Finite-input explanatory pseudocode (not a complete IEEE NaN/exception model):

```text
if !isActive || gameView == nil: return
if !frameHasBeenDrawnSinceActivate:
    tempBackgroundView.removeFromSuperview()
    tempBackgroundView.release()
    tempBackgroundView = nil
frameHasBeenDrawnSinceActivate = true
self.view.setFramebuffer()
if !openGLInitialized:
    gameView.initOpenGL()
    openGLInitialized = true
now = NSDate.timeIntervalSinceReferenceDate()
rawDT = float32(now - lastTime)
boundedDT = rawDT
if boundedDT > float32(0.1): boundedDT = float32(0.1)
else if boundedDT < 0: rawDT = boundedDT = 0
gameView.preUpdate(rawDT)
gameView.update(boundedDT, boundedDT)
gameView.render(boundedDT)
lastTime = now
self.view.presentFramebuffer()
```

The selector name accurateDT is not evidence its parameter receives rawDT.
Native loads at 0x00781dc8/0x00781dcc prove both update parameters use the same
stack slot. Float NaN, exceptional Objective-C control flow, and mutated/escaped
stack cases are not covered by this explanatory pseudocode.

## Remaining work

This recovers the outer frame orchestration, not the called gameView methods.
Next identify gameView receiver class/construction and recover initOpenGL,
preUpdate:, update:accurateDT:, render: bodies with the same source boundaries.
Do not wire this into replacement scheduling until lifecycle and argument
contracts of those callees have been separately established.
