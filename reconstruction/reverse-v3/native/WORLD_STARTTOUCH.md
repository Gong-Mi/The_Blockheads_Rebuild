# World -[startTouch:tapCount:index:] static map

Original ELF SHA-256 `733d8210…b94c7`; types `c24@0:4{CGPoint=ff}8i16i20`.
IMP `0x005b31b8`, ARM.exidx end `0x005b3278`, 48 words verified, branch-free.
PIC base `0x0105faf4` (GameView/World input family).
`tools/recover_world_starttouch.py --check` re-verifies all anchors.

## Structure (exact)

1. Spill (0x5b31c4..0x5b31e0): `index`@fp+12→ip, `tapCount`@fp+8→lr,
   then r2/r3 (point.x/y), r0 (self), r1 (_cmd) to frame — the classic
   Appportable save-all prologue, no logic.
2. State write (0x5b31e4..0x5b3200): `self->pauseIdleTimer = 0` — ivar cell
   0x005b3268 → `OBJC_IVAR_$_World.pauseIdleTimer`, offset 3264. Touch start
   unconditionally resets the idle-pause flag in the WORLD object, before any
   forwarding and independent of UI hit-test results.
3. Tail forward (0x5b3204..0x5b3258): receiver `self->uiManager`, symbol
   `OBJC_IVAR_$_World.uiManager` (ivar offset 240, cell 0x005b3270),
   selector `startTouch:tapCount:index:`
   (cell 0x005b3274), args restaged per AAPCS (ints via `mov r4,sp;
   str r1,[r4]; str r3,[r4,#4]`), `bl 0x1c281c` = `<objc_msgSend@plt>`
   (GOT slot 0x105fb18, R_ARM_JUMP_SLOT verified).
4. Return (0x5b325c): `sxtb r0` of the callee result — signed-char
   passthrough, no normalization; World's own result IS UIManager's byte.

## Consequences for the input chain

- The GameView touchIsInUI: world path (GAMEVIEW_TOUCHISINUI.md) reaches here
  only when loadComplete && !isSimulating; this method itself never checks
  either — the gate lives entirely in GameView.
- `pauseIdleTimer` is world-level touch side effect #1: it fires even when
  UIManager later reports "not in UI" (the forward is unconditional).
  Server join/leave idle semantics depend on this field; its consumption
  point is in the net/idle timer family, still unmapped — recorded as pending.
- tapCount/index are forwarded verbatim; World keeps no per-touch state here.

## Bounds

Static body map only: nil `uiManager` would yield the ObjC nil-dispatch zero
byte (0 = "touch not consumed") — plausible but UNPROVEN at runtime;
UIManager -[startTouch:tapCount:index:] internals (0x00ad7748) are a separate
method, its own pending. No gameplay wiring changed in this batch.

## Reproduce (local acceptance layer, original ELF required)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_world_starttouch.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
```
