# GameView -[touchIsInUI:] static control-flow map

Original ELF SHA-256 `733d8210…b94c7`; types `c16@0:4{CGPoint=ff}8`
(signed char in, CGPoint by value). IMP `0x0092bc54`, ARM.exidx end
`0x0092be2c`, 118 words verified against the pinned bytes
(`tools/recover_gameview_touchisinui.py --check`). PIC base `0x0105faf4` —
identical to the -[init] family, confirming same compilation unit.

This closes the `GAMEVIEW_INPUT.md` pending item "UI routing" for this method:
the two indexed-input methods forwarded through `touchIsInUI:` are now mapped
from their callee side.

## Dispatch sites (all four, with receiver provenance)

| site | selector | receiver route (reviewed loads) |
|---|---|---|
| 0x0092bd04 `bl 0x001c281c` stub | `touchIsInUI:` | `mainMenuUI` — self+ivar loaded 0x0092bc80..0x0092bc90 |
| 0x0092bd4c `blx r2` | `loadComplete` | `world` reloaded 0x0092bd24..0x0092bd3c |
| 0x0092bd98 `blx r2` | `isSimulating` | `world` reloaded 0x0092bd70..0x0092bd84 |
| 0x0092bde4 `bl` stub | `touchIsInUI:` | `world` loaded 0x0092bda8..0x0092bdc0 |

Note: both `touchIsInUI:` sites call the shared stub at `0x001c281c`, which is
`objc_msgSend@plt` — verified independently: GOT slot `0x0105fb18` carries
`R_ARM_JUMP_SLOT  objc_msgSend` (llvm-readelf -r), matching objdump's
`<objc_msgSend@plt>` label at that address. The two `blx r2` sites reach
`objc_msgSend` through a GOT cell reloaded per-call from
`0x0092bd10`/`0x0092bd5c`.

Ivar cells (symbol-resolved via __objc_ivar entries):
`OBJC_IVAR_$_GameView.mainMenuUI` (offset 0x14=20, cell 0x0092be08),
`OBJC_IVAR_$_GameView.world` (offset 0x18=24, cell 0x0092be0c).
Selector cells: `touchIsInUI:` 0x0092be14, `loadComplete` 0x0092be1c,
`isSimulating` 0x0092be20. CGPoint components spill at fp-0x18/-0x14 and are
forwarded via `[sp+0x18]/[sp+0x1c]` (menu path) and `[sp+0x10]/[sp+0x14]`
(world path).

## Decision logic (static CFG, exact branch sites)

```text
if mainMenuUI == nil (beq 0x0092bc9c) or world != nil (bne 0x0092bcc4):
    # world path
    if [world loadComplete] == 0 (sxtb, beq 0x0092bd58): return 0
    if [world isSimulating] != 0 (sxtb, bne 0x0092bda4): return 0
    return [world touchIsInUI:point]
else:
    return [mainMenuUI touchIsInUI:point]
```

Result is byte-stored (`strb r0,[fp,#-9]` at both real sites, plus the
constant-0 `strb` at 0x0092bdf8) and `ldrsb`-returned (0x0092bdfc):
signed char, no bool normalization by the method itself. 0x0092bd08/…/0x0092bdec
are the reviewed paths; 0x0092bdf0 is a compiler padding self-jump into the
constant-0 store.

## Bounds of the claim

Static body map only: which ivars are read, which selectors are sent, to which
receiver expression, under which branch condition. NOT proven here: runtime
values of `mainMenuUI`/`world` (nil dispatch would silently yield 0/false),
the callees' own behaviour (UIManager `touchIsInUI:` family lives elsewhere),
and any side effects. `loadComplete`/`isSimulating` are also read in
`GAMEVIEW_INPUT.md`'s primary/secondary gates — cross-method consistency:
touch simulation and UI hit-testing share the world's load/simulation state.

## Reproduce (local acceptance layer, requires original ELF)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_gameview_touchisinui.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
```

Machine copy: `gameview_touchisinui.json`. CI gate: listed in
`tools/validate_reverse_evidence.py` (no ELF required).

## Adapter boundary (replacement side)

Replacement `GameActivity.onTouch` currently routes: world taps hit
`handleTouchNative` mining/placement; UI widgets are Android views above the
GL surface. The original model is inverted (one view, engine-side hit-test with
UI-shadowing rule: only nil-menuUI-or-nil-world reaches world hit-testing).
The recorded rule to mirror in gameplay wiring: while `loadComplete` is false
OR `isSimulating` is true, world touch hit-test must return not-in-world;
menu overlay absorbs touches iff it exists and world is absent (cold-start
menu). Wiring change deferred to the input-loop slice.
