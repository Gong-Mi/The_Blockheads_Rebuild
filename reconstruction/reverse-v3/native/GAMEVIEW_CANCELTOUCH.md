# GameView -[cancelTouch:] static control-flow map

Original ELF SHA-256 `733d8210…b94c7`; types `v16@0:4{CGPoint=ff}8`
(void return, CGPoint by value). IMP `0x0092c638`, ARM.exidx end
`0x0092c89c`, 153 words verified against the pinned bytes
(`tools/recover_gameview_canceltouch.py --check`). PIC/GOT base `0x0105faf4` —
identical to the -[init]/-[touchIsInUI:] family, confirming the same
compilation unit.

This completes the cancel entry point of the indexed-input pair: where
`touchIsInUI:` decided UI-vs-world routing, `cancelTouch:` decides what
cancel clears and what it forwards.

## Dispatch sites (all four, with receiver provenance)

| site | selector | receiver route (reviewed loads) |
|---|---|---|
| 0x0092c6e8 `bl 0x001c281c` stub | `endTouch:` | `mainMenuUI` — self+ivar loaded 0x0092c6ac..0x0092c6c4 (cells 0x0092c868/0x0092c870, `[r1,r2]` lands on GOT slot 0x0105e168) |
| 0x0092c72c `blx r2` | `loadComplete` | `world` loaded 0x0092c704..0x0092c718 via GOT slot 0x0105e110 |
| 0x0092c778 `blx r2` | `isSimulating` | `world` reloaded 0x0092c750..0x0092c764 via GOT slot 0x0105e110 |
| 0x0092c818 `bl 0x001c281c` stub | `cancelTouch:index:` | `world` reloaded 0x0092c7d4..0x0092c7e8 (`[r1,r2]` lands on GOT slot 0x0105e110); third argument `index = 0` via `movw lr,0; str lr,[ip]` |

Note: both `bl` sites decode (from the verified instruction bytes, not
disassembler labels) to the shared stub at `0x001c281c`, which is
`objc_msgSend@plt` — verified independently: GOT slot `0x0105fb18` carries
`R_ARM_JUMP_SLOT  objc_msgSend` (llvm-readelf -r). The two `blx r2` sites
reload `objc_msgSend` from GOT import slot `0x0105b7a0`.

Ivar cells (symbol-resolved via `__objc_ivar` entries):
`OBJC_IVAR_$_GameView.mainMenuUI` (offset 0x14=20, cell 0x0092c868),
`OBJC_IVAR_$_GameView.world` (offset 0x18=24, cell 0x0092c86c),
`OBJC_IVAR_$_GameView.startTouchHasntMoved` (offset 0x1e6, cell 0x0092c894),
`OBJC_IVAR_$_GameView.primaryTouchIsActiveInUI` (offset 0x1f0, cell 0x0092c884),
`OBJC_IVAR_$_GameView.secondaryTouchIsActiveInUI` (offset 0x1fc, cell 0x0092c888).
All three touch-state ivars are single bytes (`ldrsb`/`strb`).
Selector cells: `endTouch:` 0x0092c874, `loadComplete` 0x0092c87c,
`isSimulating` 0x0092c880, `cancelTouch:index:` 0x0092c890.
CGPoint components spill at fp-0x10/-0xc and are forwarded via
`[sp+0x18]/[sp+0x1c]` (menu path) and `[sp+0x10]/[sp+0x14]` (world path).

## Decision logic (static CFG, exact branch sites)

```text
if mainMenuUI == nil (beq 0x0092c680) or world != nil (bne 0x0092c6a8):
    world path
else:
    [mainMenuUI endTouch:point]  (bl stub 0x0092c6e8); b 0x0092c840 tail

world path:
    if [world loadComplete] (sxtb) == 0 (beq 0x0092c738) -> tail
    if [world isSimulating] (sxtb) != 0 (bne 0x0092c784) -> tail
    if primaryTouchIsActiveInUI != 0 (bne 0x0092c7a8)
       or (primary == 0 and secondary == 0):
        [world cancelTouch:point index:0]  (bl stub 0x0092c818)
    if primary == 0 and secondary != 0 (bne 0x0092c7cc):
        send skipped
    startTouchHasntMoved = 0  (strb at 0x0092c838; reached BOTH by
        fall-through from the send and from the bne 0x0092c7cc)

tail (shared, all paths): primaryTouchIsActiveInUI = 0 (strb at 0x0092c85c)
```

Two structural facts worth recording:

- The menu path sends `endTouch:` — not `cancelTouch:` — to `mainMenuUI`.
  The cancel entry point maps to the menu UI's touch *end*, consistent with
  the menu having no cancel concept of its own.
- The world gate (`loadComplete` && `!isSimulating`, sxtb-signed) is exactly
  the same pair and order as the `touchIsInUI:` world path (see
  `GAMEVIEW_TOUCHISINUI.md`), and `cancelTouch:` forwards to World's
  `cancelTouch:index:` (IMP 0x005b33ac in the method map) with a literal 0
  index argument.

Claim boundary: static bounded-body map with per-instruction anchors. No
runtime receiver identity, nil-dispatch outcome, or touch-state side-effect
proof. The byte-ivars' cross-method writers (`startTouchHasntMoved` is also
consumed by the start/move chain; `primaryTouchIsActiveInUI` is presumably
set by the touch-begin path) are outside this body.
