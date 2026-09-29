# The input front — first slice: `UIManager -startTouch:tapCount:index:` (0x00AD7748, 576w)

The save/load front is closed; this is the next front, entering the touch
chain one link downstream of the already-recovered GameView/World pair
(`GameView -startTouch:withTouch:withEvent:` → the World route →
`World -startTouch:...` → here).

## What the body does (annotated listing: `disasm_uimanager_starttouch.txt`)

A priority-ordered UI router. Each block reads one UI ivar, calls its
`startTouch:tapCount:`-family selector, and stores the result:

| order | ivar (offset) | call |
|---|---|---|
| 1 | `tcUI@32` (+ `tcUIDisplayed@40`) | `startTouch:tapCount:` |
| 2 | `worldUI@20` | `startTouch:tapCount:paused:index:` |
| 3 | `pauseUI@24` (+ `hidePauseUI@148`) | `startTouch:tapCount:` |
| 4 | `cameraUI@100` | `startTouch:tapCount:` |
| 5 | `dpad@36` (gated by `[dpad displayed]`) | `startTouch:tapCount:index:` |
| 6 | `worldUI@20` (via `currentTouchIsInAnyButtons@154`) | `startTouch:tapCount:index:` |
| 7 | `uiViews@140` fast enumeration (`mapDisplayed@152` context) | `touchIsInViewAtAll:` then `startTouch:tapCount:` per view |

The stores of interest are `currentTouchIsInAnyButtons@154` (strb) and the
per-UI "displayed"-family flags; the many stack stores are argument setup.

## Two executed regimes (harness)

- **empty UI state** (zeroed instance): every receiver is nil —
  `displayed(recv=0x0)`, `startTouch:tapCount:index:(recv=0x0)`,
  `import(memset)`, `countByEnumeratingWithState:objects:count:(recv=0x0)` —
  the router falls through and returns **0**;
- **UIs present** (`--seed` sets `worldUI@20`, `pauseUI@24`, `tcUI@32`,
  `dpad@36`, `cameraUI@100` to stub-region pointers): the router calls
  `[pauseUI startTouch:tapCount:]` then `[worldUI startTouch:tapCount:paused:index:]`
  and returns **1** (the touch is reported consumed).

## The UI family base: GameUIView (0x00CA9D84..0x00CAA248, 15 methods)

The router's `uiViews` family resolves to **GameUIView** (23 of the 38
`startTouch:tapCount:` classes carry `super == GameUIView`; the other 15
just lack their superref cell in the metadata). The whole base is
consecutive in .text and now decoded
(`disasm_gameuiview_all.txt`):

| method | base behaviour |
|---|---|
| `displayed` | `return displayed@4` |
| `setDisplayed:` | `displayed@4 = arg` + resets `displayStartAnimationTimer` |
| `loadResources` | `resourcesLoaded@16 = 1` |
| `canDismiss` | `return 1` |
| `stopBlockheadInteractingWhenDismissed` | `return 0` |
| `dismissWhenBlockheadStopsInteracting` | real body: consults `stopBlockheadInteractingWhenDismissed` |
| `touchIsInUI:` / `touchIsInViewAtAll:` | `return 0` (the base is never hit) |
| `startTouch:tapCount:` | `return 0` (not handled) |
| `moveTouch:` / `endTouch:` | no-ops |
| `windowInfoChanged:` | no-op (subclasses that care override it) |
| `center:` | builds a Vector2 via 0x4D0480 |
| `render:translation:pinchScale:` | the only substantial base method: lazily calls `loadResources` when `resourcesLoaded@16 == 0`, then the appear-animation (`displayStartAnimationTimer`, `displayStartScale@12`, a 0.2 ease constant) into the quad draw path (0x1C3F98 / 0x1C2954 / 0x582A14) |

So the family contract is: **the base answers "not handled / not in view"
everywhere**, and each panel subclass overrides the touch/visibility methods
with its own hit test and handling.

### The router's UI blocks, modelled from the code

Two blocks are decoded and share one shape:

```
if (UI) {                                  // the block's own ivar
    r = 0;
    if (!gate) r = [UI startTouch:tapCount:point, tapCount];
    if (!r)     r = [worldUI startTouch:tapCount:paused:index:point,
                     tapCount, 1, index];
    handled = 1;                            // [fp-0x19]
    return 1;
}
```

- block 1 (0x00AD77A8..0x00AD78AC): gated by `tcUIDisplayed@40`;
- block 2 (0x00AD78B0..0x00AD7A34): gated by `hidePauseUI@148`;
- a nil `UI` falls through to the next block (cameraUI@100 follows block 2).

And the tail blocks (decoded the same way):

- the cameraUI block (0x00AD7A38..): `if (cameraUI)` — the two-call shape
  (`startTouch:tapCount:` then, on zero, `startTouch:tapCount:paused:index:`),
  but the block stores the MERGED result as handled and returns it (0 when
  both calls answer zero) — unlike blocks 1/2 which store an unconditional 1;
- the dpad block (0x00AD7B70..): gated by `[dpad displayed]` (a real method
  call — the stub answers 0, which is why cases 0/1 show the call and move
  on); on a displayed dpad it calls `[dpad startTouch:tapCount:index:...]`
  and only a nonzero result sets handled + returns 1 — a miss FALLS THROUGH
  (no worldUI-paused fallback here);
- the worldUI block (0x00AD7C3C..): `r = [worldUI startTouch:tapCount:index:…]`
  then **`currentTouchIsInAnyButtons@154 = r`** (a real state write), and
  `if (r || mapDisplayed@152)` exits, else runs the `uiViews@140`
  enumeration (the `memset` + countByEnumerating tail the empty-UI cases
  show).
- the uiViews loop body (0x00AD7CFC..0x00AD7FA8, the fast enumeration over
  `uiViews@140`): per view `[view displayed]` (0 -> skipped), then
  `[view startTouch:tapCount:]` (nonzero -> `currentTouchIsInAnyButtons@154 = 1`
  and return 1), else `[view touchIsInViewAtAll:]` — a view that contains
  the point ENDS the search there (returning @154), and an exhausted
  enumeration returns @154 too (the second `countByEnumerating` call).

The complete chain, then, is: block 1 `tcUI` (gated on `tcUIDisplayed@40`) ->
block 2 `pauseUI` (nil falls through; `hidePauseUI@148` set returns 1 with NO
call at all) -> block 3 `cameraUI` (nil falls through; merged result is the
return) -> block 4 `dpad` (`[dpad displayed]` gates; a miss falls through) ->
block 5 `worldUI` (the `currentTouchIsInAnyButtons@154` write; `r != 0` or
`mapDisplayed@152` ends the route) -> block 6 the `uiViews` enumeration.

So the router's pattern is "one UI consumes the touch, the world is notified
with `paused:`" and the method returns 1; the worldUI-paused fallback runs
only when the UI's own handler returned zero. Every block is now decoded and
the router's model is fully semantic (`run_ui_router`, below): the
differential's 19 cases (tools/test_specials_arm.py, cases 0..18) walk every
block and branch — the gate variants, both fallback shapes, the dpad
hit/miss, the `@154` write, the `mapDisplayed` exit and the enumeration's
skip/handle/in-view/exhausted paths — with the call sequences, the `@154`
byte and the return value all compared against Unicorn executions of the
original body at -O0/-O2. No case-fitted strings remain. The next slice is
the subclasses' overrides (e.g. `CraftUI`, `DPad`, `BlockheadUI`).

## The first subclass overrides: DPad (0x0070561C..0x00705A1C)

**All 23 GameUIView children override all five touch-contract methods**
(`startTouch:tapCount:`, `touchIsInUI:`, `touchIsInViewAtAll:`, `moveTouch:`,
`endTouch:`) — a family-wide convention. Size survey from the method table
gaps: the overrides are tens to hundreds of words (BlockheadUI
`touchIsInViewAtAll:` 99w, CraftUI 95w, DPad 232w; the accessor pairs
~15-17w).

DPad decoded and differentially executed (`disasm_dpad_touch.txt`):

- `touchIsInUI:` (24w) is a pure forward: `return [self
  touchIsInViewAtAll:point]` (the msgSend at 0x00705664, sxtb for the BOOL);
- `touchIsInViewAtAll:` (232w) is the rotated-diamond hit test, decoded exactly:
  1. `x1 = point.x - windowInfo[+8]`, `y1 = point.y - windowInfo[+0xc]`;
  2. `px = (x1 - X) - 80` where `X` is `((-windowInfo[+8]) + windowInfo[+0x10])
     + 40` on the left side and `(windowInfo[+8] - windowInfo[+0x14]) - 200`
     on the right side (`rightSide@160` selects the mirrored layout);
     `py = (y1 - ((windowInfo[+0x1c] - windowInfo[+0xc]) + 40)) - 80`;
  3. the 0x0070591C helper rotates `(px, py)` by the movw/movt constant
     **0xBF490FDB = -pi/4** via `sinf`/`cosf` (PLT 0x1C2B34 / 0x1C2B58; the
     softfp ABI rides the arg/return in R0 — the caller's `vmov` pair):
     `out.x = x*cos - y*sin`, `out.y = y*cos + x*sin`;
  4. the result is `-80 < out.x < 80 && -80 < out.y < 80` — every edge
     EXCLUSIVE (four fused compares; the 0x4BDAAC identity thunk hands the
     vector pointer back to the compares).

  Two decode corrections the differential caught (the first pass had both
  wrong and the day-one ARM run returned 0 where the model said 1): the
  y-chain's middle constant is **+40** (the same pool word as the left-side
  `X`), not -80; and the angle is `0xBF490FDB` (-pi/4) — reading the
  `movw #0x0fdb` / `movt #0xbf49` pair as one word had produced the
  non-constant 0xBF49FDB6. A mid-run probe (reading the method's stack at
  the first compare) showed the true rotated vector, and both corrections
  made model and ARM agree bit-for-bit.

### DPad enters the differential (11 cases, types 78..79)

`DPadInUI` 0/1: the forward with the callee's reply pinned 0/1 (via `ret1`
on self). `DPadRect` 0..8: center / +rx out / +ry out / corner in / corner
out on the zero frame, then three cases that would FLIP if a term were
omitted — `windowInfo[+0x10]`, `windowInfo[+0x1c]`, and the rightSide
layout — plus the right-side edge case. The body's own calls are exactly
`import(sinf),import(cosf)` (everything else is direct .text helpers); the
harness answers `sinf`/`cosf` with the true float values (a platform-libm
stand-in) and every case keeps a wide margin to the +-80 edges.

## The third panel: BlockheadUI (0x006FD188..0x006FDF24) — decoded

All five overrides are decoded and executed (`disasm_blockheadui_touch.txt`
/ `_starttouch.txt` / `_moveend.txt`):

- `touchIsInViewAtAll:` (99w) — the own-rect test with its own numbers:
  local = point - windowInfo(+8/+0xc) - translationOffset (@184/188);
  `x in (-120, 120)`, `y in (-144, 142)`, every edge exclusive;
- the four delegation chains share ONE order and ONE gate:
  `getWorkbenchButton@80`, `nameEditButton@96`, then either
  `stopButton@92` and RETURN (when `stopButtonDisplayed@76` is set) or
  `sleepButton@84` + `meditateButton@88`:
  - `touchIsInUI:` (226w) / `startTouch:tapCount:` (228w) — short-circuit,
    first nonzero wins (the children answer via `touchIsInUI:` / the
    one-argument `startTouch:`);
  - `moveTouch:` (159w) / `endTouch:` (159w) — ALL children, no
    short-circuit, void.

BlockheadUI enters the differential (28 cases, types 80..84):

- `BlockheadUIRect` 0..7: the four exclusive edges + the centre, and three
  cases that would FLIP if the translationOffset / windowInfo terms were
  dropped from the rebase;
- `BlockheadUIInUI` / `BlockheadUIPress` 0..7: all-miss and each child
  alone, with `expect_recv` proving each case's receiver order — case 4 is
  the gate proof: with `stopButtonDisplayed` set the ARM's call list ENDS
  at stopButton (0x60020800) in BOTH chains;
- `BlockheadUIMove` / `BlockheadUIEnd` 0/1: the four-call chain and the
  gate's three-call early exit, receiver-verified per case.

## The constant-verdict panels (types 85..96) — decoded

Five panels' rect / in-UI bodies turn out to be LITERALS: the point is
rebased into dead locals (the `windowInfo(+8/+0xc)` reads happen; the
results are discarded) and the method returns the class constant
(`movw lr, #N; sxtb r0, lr`) — no receiver is ever messaged:

| panel | `touchIsInViewAtAll:` | `touchIsInUI:` | note |
|---|---|---|---|
| MapUI (0x009CB460, 96..96..12..7w) | 0 | 0 | press returns 0; move/end are 7w stubs |
| OptionsUI (0x008477C8) | 1 | 0 | |
| ShareUI (0x009C3244) | 1 | 0 | |
| PauseUI (0x009E8E70) | 1 | (79w, undecoded) | |
| MainMenuUI (0x00A09CF0, windowInfo@128) | 1 | 1 | |

All twelve bodies execute under Unicorn (17 cases): the const-0 panels take
an inside-candidate point and still answer 0, the const-1 panels take a
far-away point and still answer 1 — the invariance IS the assertion. The
`windowInfo` offsets differ per class (96; MainMenuUI 128) and are part of
the fixture.

## The WorkbenchProgressBarUI panel (types 97..101) — decoded

`disasm_workbenchprogressbarui_touch.txt` (the whole family, 327w):

- `touchIsInViewAtAll:` (95w) is the CraftUI-shaped four-compare rect with
  its own numbers: local = point - windowInfo(+8/+0xc) -
  translationOffset(@120/@124); `x in (-120, 120)`, `y in (0, 102)`, every
  edge exclusive;
- `touchIsInUI:` (59w) rebases into dead locals and returns 0;
  `startTouch:tapCount:` (61w) returns 0; `moveTouch:` / `endTouch:`
  (56w each) are empty void bodies — no receiver is ever messaged.

11 cases (the five edges + two term-flips + the four constants) execute
under Unicorn; `wbpbarui_touch_is_in_view_at_all` + the two decoded
constants are the model.

## The CameraUI panel (types 102..106) — decoded

`disasm_cameraui_touch.txt` (341w): `touchIsInViewAtAll:` (32w) is the
constant **1** (dead rebase, windowInfo@96); `touchIsInUI:` (78w) and
`startTouch:tapCount:` (99w) are the two-child OR — `cancelButton@104`
then `takePhotoButton@108`, short-circuit, the press using the one-argument
`startTouch:`; `moveTouch:` / `endTouch:` (66w each) message BOTH children
in that order. 10 cases (the const-1 far-point control, both children alone
+ all-miss per chain, the void orders receiver-verified) execute under
Unicorn.

## The AddFuelUI panel (types 167..171) — decoded

`disasm_addfuelui_touch.txt` (800w): `touchIsInViewAtAll:` (95w) — x in
(-120, 120), y in (0, 108). The four chains NSFastEnumeration over
`fuelButtons@40`: `touchIsInUI:` (180w) / `startTouch:tapCount:` (183w)
walk the batch and BREAK on the first true reply (the exhausted batch
re-requests countByEnumerating once — the trace carries the
`import(memset)` prologue); `moveTouch:` / `endTouch:` (171w each)
message EVERY element (same prologue/walk, no break). 15 cases execute
under Unicorn.

## The SleepProgressUI panel (types 162..166) — decoded

`disasm_sleepprogressui_touch.txt` (565w): `touchIsInViewAtAll:` (95w) —
x in (-120, 120), y in (0, 110), all edges exclusive. `touchIsInUI:`
(132w) / `startTouch:tapCount:` (138w): local = [abortButton@120 ...];
the **isMeditation@140 gate sits BEFORE the second child** — when set,
completeButton@124 is never reached; otherwise the standard short-circuit
OR. `moveTouch:` / `endTouch:` (100w each): abortButton always,
completeButton only when !isMeditation. 19 cases execute under Unicorn.

## The JetPackUI panel (types 157..161) — decoded

`disasm_jetpackui_touch.txt` (477w): `touchIsInViewAtAll:` (95w) — local =
point - windowInfo(+8/+0xc) - translationOffset(@144); x in (-120, 120),
y in (0, 108), all edges exclusive. `touchIsInUI:` (103w) /
`startTouch:tapCount:` (105w) are the two-child OR in the order
addFuelButton@44, freeFlightButton@48 (short-circuit);
`moveTouch:` / `endTouch:` (87w each) message BOTH children. 15 cases
execute under Unicorn.

## The HungerUI panel (types 152..156) — decoded

`disasm_hungerui_touch.txt` (393w): `touchIsInViewAtAll:` (95w) — local =
point - windowInfo(+8/+0xc) - translationOffset(@152); x in (-80, 80),
y in (0, 92), all edges exclusive. The four chains message the SINGLE
child eatButton@68: `touchIsInUI:` (69w) / `startTouch:tapCount:` (93w)
return its reply; `moveTouch:` / `endTouch:` (68w each) are void.
13 cases execute under Unicorn.

## The ControlOptionsUI panel (types 147..151) — decoded

`disasm_controloptionsui_touch.txt` (374w): `touchIsInViewAtAll:` (32w)
is the constant 1 (dead rebase); `touchIsInUI:` (32w) the constant 0.
`startTouch:tapCount:` (114w) messages ALL FOUR [OKButton@104,
tiltControlButton@112, directControlButton@120, dpadSideButton@128] with
the one-arg `startTouch:` and returns the constant local 0;
`moveTouch:` / `endTouch:` (98w each) message the same four. 7 cases
execute under Unicorn.

## The AddCreditUI panel (types 142..146) — decoded

`disasm_addcredit_ui_touch.txt` (365w): `touchIsInViewAtAll:` (32w) is
the constant 1 (dead rebase); `touchIsInUI:` (32w) the constant 0.
`startTouch:tapCount:` (111w) gates on the inProgress@160 byte first:
set -> return 1 with ZERO child calls; clear -> message ALL THREE
[cancelButton@128, add1WeekButton@132, add1MonthButton@136] with the
one-arg `startTouch:` and return the constant 0 (the replies land in
dead slots). `moveTouch:` / `endTouch:` (95w each) gate the same way,
then message all three. 10 cases execute under Unicorn.

## The FreeOfferUI panel (types 137..141) — decoded

`disasm_freeofferui_touch.txt` (350w): `touchIsInViewAtAll:` (32w) is the
constant 1 (dead rebase); `touchIsInUI:` (32w) the constant 0.
`startTouch:tapCount:` (108w): local = [exitButton@152 startTouch:pt],
then for i in 0..offerCount@156-1: if (local == 0) local =
norm([buyButton[i] startTouch:pt]) — buyButton@36 is an ARRAY of button
pointers, so the walk calls one entry per index until the first true and
iterates the rest with no calls; returns the OR.
`moveTouch:` / `endTouch:` (89w each) message exitButton then EVERY
buyButton[i] (the same loop, no short-circuit). 9 cases execute under
Unicorn (the constant verdicts, the three press walks, both void loops).

## The InventoryFullUI panel (types 132..136) — decoded

`disasm_inventoryfullui_touch.txt` (328w): `touchIsInViewAtAll:` (95w) —
x in (-120, 120), y in (0, 126), all edges exclusive;
`touchIsInUI:` (58w) and `startTouch:tapCount:` (63w) both return the
constant 0 after full (dead) rebases; `moveTouch:` / `endTouch:` (56w
each) are the rebases alone. No child calls anywhere. 12 cases execute
under Unicorn.

## The SoundOptionsUI panel (types 127..131) — decoded

`disasm_soundoptionsui_touch.txt` (323w): `touchIsInViewAtAll:` (32w) is
the constant 1 (a dead windowInfo read precedes it); `touchIsInUI:` (32w)
the constant 0. `startTouch:tapCount:` (95w) messages ALL THREE children
[OKButton@104, musicSlider@112, soundSlider@120] with the one-arg
`startTouch:` and returns the constant local 0 — the three replies land in
dead stack slots (an original-code quirk pinned by the differential).
`moveTouch:` / `endTouch:` (82w each) message all three. 7 cases execute
under Unicorn.

## The TradingPostBuyUI panel (types 122..126) — decoded

`disasm_tradingpostbuyui_touch.txt` (573w): `touchIsInViewAtAll:` (98w) —
x in (-82, 82), y in (-16, 190). ALL four chains gate on the
`closed@172` byte first: closed != 0 returns 0 with ZERO child calls
(move/end skip too). Open, `touchIsInUI:` (130w) /
`startTouch:tapCount:` (131w) are the two-child OR countSlider@164 ->
buyButton@192, short-circuit. The inUI fall-through messages buyButton
with the one-arg `startTouch:` — an original-code quirk the differential
pins via both the receiver trace and the pinned reply. `moveTouch:` /
`endTouch:` (107w each) message BOTH children. 18 cases execute under
Unicorn.

## The RegenerateUI panel (types 117..121) — decoded

`disasm_regenerateui_touch.txt` (518w): `touchIsInViewAtAll:` (95w) — local
= point - windowInfo(+8/+0xc) - translationOffset(@128); x in (-120, 120),
y in (0, 184), all edges exclusive. `touchIsInUI:` (122w) /
`startTouch:tapCount:` (127w) are the two-child OR in the order
`dieButton@120`, `completeButton@124` (short-circuit: a miss on die falls
through to complete; the press uses the one-arg `startTouch:`);
`moveTouch:` / `endTouch:` (87w each) message BOTH children. 14 cases
execute under Unicorn.

## The WearUI panel (types 112..116) — decoded

`disasm_wearui_touch.txt` (416w): `touchIsInViewAtAll:` (118w) — local =
point - windowInfo(+8/+0xc) - translationOffset(@152); the x compares run
in DOUBLE (`vcvt.f64.f32` + `vmul.f64` by 0.5) against `+-w/2` where w/h is
the EMBEDDED float pair `frameSize@28/@32`, y in `(0, h - 16)` in f32 — all
edges exclusive. The chains message the SINGLE child `wearButton@60`:
`touchIsInUI:` (69w) / `startTouch:tapCount:` (93w) return its reply,
`moveTouch:` / `endTouch:` (68w each) are void. 14 cases execute under
Unicorn (the five edges, the w=100/h=50 and w=200/h=200 term-flips, the
single-child chains).

## The PetUI panel (types 107..111) — decoded

`disasm_petui_touch.txt` (418w): `touchIsInViewAtAll:` (98w) — local =
point - windowInfo(+8/+0xc) - translationOffset(@136), `x in (-120, 120)`,
`y in (-16, 114)`, all edges exclusive; the four chains message the SINGLE
child `nameEditButton@52`: `touchIsInUI:` (91w) / `startTouch:tapCount:`
(93w) return its reply, `moveTouch:` / `endTouch:` (68w each) are void.
13 cases execute under Unicorn (the five edges + two term-flips + the
single-child chains).

## The composition pattern: CraftUI (0x00B80EB4..0x00B817A4) — decoded

CraftUI's five override bodies are decoded from the instruction stream
(`disasm_craftui_touch.txt`, `disasm_craftui_starttouch.txt`); the family's
composition convention, corrected against the code:

- every body begins with the same frame math: `local = point -
  windowInfo(+8/+0xc) - translationOffset(@212/@216)` (translationOffset is
  the pair of floats at 212/216; the two `bl 0x4BDAAC` calls are the
  identity thunk that hands back the `self+212` pointer);
- `touchIsInViewAtAll:` (95w) is the panel's own-rect test: 260 x 302 with
  **every edge exclusive** — `x > -130 && x < 130 && y > 0 && y < 302`
  (constants from the literal pool: 0xC3020000 / 0x43020000 / 0x43970000 =
  -130 / 130 / 302), four fused compares;
- `touchIsInUI:` (134w) is the children's OR ONLY —
  `[scrollingButtons@148 touchIsInUI:]`, `[craftButton@208 touchIsInUI:]`,
  `[countSlider@164 touchIsInUI:]` in that order, first nonzero wins
  (msgSend at 0x1C281C). **Correction:** an earlier note said this method
  "repeats the rect test" — the instruction stream has no such compares;
  the rect lives in `touchIsInViewAtAll:` alone, and a panel's "in UI" is
  its widgets' aggregate, not `rect OR widgets`;
- `startTouch:tapCount:` (137w) runs the same frame math, then delegates
  `[scrollingButtons startTouch:]`, `[craftButton startTouch:]`,
  `[countSlider startTouch:]` — note the **one-argument** `startTouch:` the
  widget layer implements — first nonzero wins, no own-rect gate;
- `moveTouch:` (103w) / `endTouch:` (103w) call **all three** children, in
  the OTHER order the listing attests — `craftButton`, `countSlider`,
  `scrollingButtons` (void; the mirrored order of the touch methods).

The same tiny helpers recur across DPad and CraftUI: 0x4D0480 (a 12-word
Vector2 builder — byte-identical twins live at 0x00765D80 and 0x006F1B84),
0x4BDAAC (an identity thunk returning its argument) and 0x1C281C (msgSend).

### CraftUI enters the differential (16 cases, types 73..77)

The five bodies execute under Unicorn against `run_ui_router`'s module
neighbours in `ui_touch_router.*` (`craftui_touch_is_in_view_at_all`,
`craftui_touch_is_in_ui`, `craftui_start_touch`, `craftui_move_touch`,
`craftui_end_touch`):

- `CraftUIRect` 0..5: inside / `x >= 130` / `x == -130` / `y == 0` /
  `y == 302` / the shifted frame (window 100,60 + offset 30,20) — the four
  exclusive edges and the subtraction order;
- `CraftUIInUI` / `CraftUIPress` 0..3: all-miss (3 calls, 0) and each
  child alone (short-circuit) — with `expect_recv` pinning the ARM's
  actual receiver order (SB, CB, CS);
- `CraftUIMove` / `CraftUIEnd`: the three calls in the CB, CS, SB order —
  `expect_recv` proves the order at the receiver level (the stripped
  selector labels cannot distinguish same-selector calls); the void return
  registers are recorded, not compared.

The negative control ran: flipping the Move expectation fails the
assertion and prints the ARM's true order
(`moveTouch:(recv=0x…700), (recv=0x…800), (recv=0x…600)`).

## The delegation pattern: CraftUI -startTouch:tapCount: (137w)

`disasm_craftui_starttouch.txt` shows the handling side mirrors the
visibility side: after the same window/translationOffset frame math (the
same small geometry kit), the panel **delegates to its widget children in
order** — `[scrollingButtons@148 startTouch:]`,
`[craftButton@208 startTouch:]`, `[countSlider@164 startTouch:]` — taking
the first non-zero (handled) result (sxtb after each msgSend at 0x1C281C).

So the family decomposes cleanly:
- **GameUIView** (base): "not handled / not in view" defaults + the render
  animation;
- **panels**: own-rect test, then OR/delegate to their widget children;
- **widgets** (buttons, sliders, scrolling lists): the actual behaviours.

The UIManager router's flat pass over `uiViews@140` is therefore a
recursive descent expressed flat — and a full router *model* needs the
widget-level behaviours, which is the next frontier.

## The widget layer: the MJ toolkit (MJView / MJButton)

The widgets the panels delegate to are members of a small in-house UI
toolkit. 14 classes implement the widget-level pair `startTouch:` +
`touchIsInUI:` (the one-argument forms), rooted at:

- **MJView** (22 methods): geometry (`initWithFrame:cache:windowInfo:`,
  `frame`/`setFrame:`, `windowInfo`, `color`/`setColor:` (an `MJColor`
  struct), `alpha`, `hidden`, `ignoreEvents`), subviews
  (`addSubview:`/`removeSubview:`), the touch contract
  (`touchIsInUI:` 176w, `startTouch:` 176w, `moveTouch:` 156w,
  `endTouch:` 156w, `hoverMove:` 156w) and `renderFrame:projectionMatrix:`
  (271w);
- **MJButton** (50 methods, an MJView subclass): two-layer titles
  (`setTitle:`/`setTitleB:` + alignments + offsets), the texture set
  (background / selected / highlighted / highlighted-selected / glyph, each
  with its A/B variants), `setEnabled:`, `setSelected:`, `setHighlighted:`,
  `tapAnimationDisabled`, `hoverSelectedDisabled`, and a 3071w
  `renderFrame:projectionMatrix:`.

The concrete widgets on top: `InventoryButton`, `NetPlayerButton`,
`ScrollingButtons` (+ Paint/TradePortal variants), `ScrollingListTradePortal`,
`ScrollingNetPlayerButtons`, `TableViewUI`, `SearchResultsUI`,
`TradePortalGraph`, `MJControl`, `CreateCustomOptionsUI`, `NetPlayerUI`.

### The three-layer picture

1. **UIManager** — the flat router over the panels (`uiViews@140`);
2. **GameUIView panels** — own rect + OR/delegate to widget children;
3. **MJView/MJButton widgets** — the toolkit's own touch contract (and the
   concrete widgets' behaviours on top).

### MJView's touch contract, decoded (0x006614A8..0x00661A28)

`disasm_mjview_touch.txt` — both 176w methods share one shape:

1. `[self hidden]` -> return 0 / not handled;
2. `[self ignoreEvents]` -> return 0 / not handled;
3. the fast enumeration over `subviews@44`
   (`countByEnumeratingWithState:objects:count:`) **recursing into each
   subview's `touchIsInUI:` / `startTouch:`** — the descent that bottoms out
   at the concrete widgets;
4. the view's own frame test (the 0x1C2924 / 0x1C2E28 codes on these
   paths are `memset` and the fast-enumeration mutation guard — compiler
   housekeeping, per PLT_VENEERS.md, not geometry);
5. `startTouch:` stores the aggregate at a local (`strb [fp,#-0x21]`) and
   returns it — the "handled" flag the panels aggregate in turn.

With this the whole touch pipeline's structure is closed end to end:
`UIManager` router -> `GameUIView` panels (rect + OR/delegate) -> `MJView`
widgets (gates + subview recursion + frame test) -> concrete widget
behaviours.

### MJView -renderFrame:projectionMatrix: — the render walk mirrors the touch walk

`disasm_mjview_render.txt` (271w): the `hidden@4` gate short-circuits, the
own quad is set up (the `powf` easing is `__wrap_powf`, PLT 0x1C3F98), then
the fast enumeration over `subviews@44` recursing into
`[subview renderFrame:projectionMatrix:]` — the same gates + self + children
shape as the touch walk. The render front's next slice is the quad pipeline
those leaf calls bottom out in.

### The render front: the base recurses, the leaves paint

`MJView -renderFrame:projectionMatrix:` (271w) turns out to be a **pure
container**: the `hidden@4` gate, then the subview enumeration calling
`[subview renderFrame:projectionMatrix:]` — **no draw call of its own** (the
`memset`/enumeration-mutation codes are the loop housekeeping). So the
render front's real body is in the leaf painters.

**MJButton -renderFrame:projectionMatrix: (3071w)** — the button painter
(`disasm_mjbutton_render.txt`), structure read from its selector/ivar
references:

- its own GL program: `shader@108` with a cached `uniformLocations` array
  (six `intValue` / `objectAtIndex:` lookups pushing the per-part uniforms,
  including the atlas `maxS`/`maxT`);
- the state-driven texture set: `backgroundTexture@112`,
  `backgroundSelectedTexture@116`, `backgroundHighlightedTexture@120`,
  `backgroundHighlightedSelectedTexture@124` selected from
  `isSelected@168` / `hoverSelectedDisabled@169` / `Control.hover@68` /
  `Control.enabled@71` / `View.color@28`;
- the two glyph layers (`glyphTexture@132`, `glyphTextureB@192`,
  `glyphColor@152`) and the two title views (`titleView@128`,
  `titleViewB@248`);
- the tap animation: `lastRenderTime@264` against
  `timeIntervalSinceReferenceDate` with `startTouchAnimationTimer@96` (the
  timer `startTouch:`/`endTouch:` reset).

The next slice: the quad pipeline the shader path feeds (the leaf calls'
GL side), and the panels' own render overrides (e.g. DPad's 1960w).

### The traversal, modelled: `reconstruction/recovered/ui_touch_router.*`

The decoded traversal semantics are now a module (CTest `ui_touch_router`,
linked into the production library alongside `tree_growth`): a `Node`
(rect + the MJView `hidden` / `ignoreEvents` gates + the ordered
`subviews` + the `displayed` gate) whose `touch_is_in_ui` / `start_touch`
implement the gates -> subview recursion -> frame test shape, and the
UIManager-style `route()` flat pass (a non-displayed view is skipped; the
first in-UI view wins; the touch is offered in order until one handles it).
The test pins the gates, the subview order, the panel's own-rect OR and the
router pass — the structure the listings attest, with the concrete widgets'
behaviours left to their own layer.

Next to it, `run_ui_router` is the router's FULL block chain (the section
above): `RouterInputs` carries the four gates and the six receivers,
`RouterTrace` is the compared artifact — the selector sequence (with the
enumeration's `import(memset)` housekeeping), the
`currentTouchIsInAnyButtons@154` byte and the returned value. The bridge
(`tools/specials_arm_bridge.cpp`, type 72) drives exactly this model with
the differential's per-case receiver replies — `recovered_ui_seq`,
`recovered_ui_img` and `recovered_ui_ret` are all computed from
`run_ui_router`, so the ARM differential now judges the model, not
case-fitted strings.

The panel layer followed: `craftui_touch_is_in_view_at_all` (the 260 x 302
rect with exclusive edges), `craftui_touch_is_in_ui` / `craftui_start_touch`
(the children's SB, CB, CS short-circuit) and `craftui_move_touch` /
`craftui_end_touch` (all three, CB, CS, SB) model CraftUI's five overrides;
types 73..77 drive them from the same per-case fixtures.

### The control behaviours, modelled: `ui_control.*` (MJControl)

`disasm_mjcontrol_all.txt` decoded the widget layer's control base
(0x009F6198..0x009F7470) — ivars `target@60`, `action@64`, `hover@68`,
`wasClicked@69`, `receivedTouchStart@70`, `enabled@71`,
`sendsEventOnTouchStart@72`, `eventFrame@80`, `startTouchAnimationTimer@96`:

- the four touch methods share the gates (MJView `hidden@4` / `ignoreEvents`,
  plus `enabled@71`); `startTouchAnimationTimer@96` is a **float** the press
  sets to 1.0 (the execution-level trace below settles it — an earlier note
  called it a double) then the `eventFrame@80` test (helper 0x009F66F0) with
  the edge chain 0x009F744C/0x009F74A8/0x009F7504/0x009F7560;
- `startTouch:` sets `hover@68 = 1`, and on a hit: if
  `sendsEventOnTouchStart@72` -> `sendAction`, the
  `startTouchAnimationTimer@96` reset, the `clickDown.wav` sound, and
  `receivedTouchStart@70 = 1`;
- `endTouch:` resets `receivedTouchStart@70` / `hover@68`, and on a hit: if
  the start did not send -> `sendAction`, the `click.wav` sound, and
  `wasClicked@69 = 1`;
- `sendAction` (50w): `[target@60 performSelector:action@64 withObject:…]`;
- `cancelAnyTouchStarts`: `receivedTouchStart@70 = 0`.

`ui_control.cpp` models exactly that lifecycle (CTest `ui_control`, in the
production library), pinned by `tools/test_ui_control.cpp`: the gates, the
send-on-start vs send-on-release flag, the lift-outside no-click, the hover
membership, the cancel path.

#### MJView's base has NO self test — the recursion only (settled)

`disasm_mjview_touchisinui.txt` settles it: past the two gates the body is
the subview fast enumeration and nothing else. The `blx` I first read as a
"frame-test helper" is the ordinary `objc_msgSend` for
`countByEnumeratingWithState:objects:count:` (the saved pointer comes from
the same basic block that sets the enumeration state); its first call on an
empty `subviews` returns 0 and the method returns 0 immediately at the
`beq` — **the point is never looked at**. So the seeded inside case's 0 is
correct behaviour, not a harness artefact, and the model's rule is:
`touch_is_in_ui` = the gates + the subviews' OR, with the self-rect test
belonging to the panel subclasses (`handles_own_rect` in
`ui_touch_router`). All four MJView cases (inside/outside empty + the two
gates) are in the differential now.

### The UI front enters the ARM differential

`tools/test_specials_arm.py` (the general differential engine) gained what
the UI methods need: `--r2r3-floats` (CGPoint arguments in r2:r3) and a
generalized super channel (a real `[super startTouch:point]` is answered by
name; only the loaders' synthetic selector keeps the stub-super path). With
`MJControl` entered (`startTouch:` 0x009F6894, superref 0x00E8BE18) the press
EXECUTES and is observable:

```
--- MJControl ret=0x00000001
    super(startTouch:)          ; the MJView base answers 0
    instance(recv=0xe91fe8)     ; [SoundManager instance]
    multiSoundNamed:(recv=0x0)  ; the clickDown sound
    play(recv=0x0)
    image: hover@68 = 1, receivedTouchStart@70 = 1, @96 = 1.0f
```

That trace is the UI front's first execution-level evidence (the state
machine's writes are the compared artifact, as with the save front). The
bridge model + cases + guard are the next slice.

## The scrolling list: ScrollingButtons -moveTouch: (490w)

`disasm_scrollingbuttons_touch.txt` — the horizontal craft list's drag
logic. Ivars: `craftableItemButtons@72` (the buttons), `xScroll@104`,
`scrollVelocity@108`, `lastX@112`, `startX@116`, `scrollInProgress@120`,
`startTouchWasInView@121`, `workbench@68`.

The body: takes the drag delta against `lastX@112`, toggles
`scrollInProgress@120`, iterates `craftableItemButtons@72`
(`countByEnumeratingWithState…`), applies the clamp through `setXScroll:`
(velocity written to `scrollVelocity@108`), calls the 0x00765D80 Vector2
builder, then runs **two further enumerations forwarding the
event to every button** — `[button endTouch:]` (0x00765AB0) and
`[button moveTouch:]` (0x00765C9C) — so each visible button tracks the
drag for its own hover/highlight state, and finally stores the new
`xScroll@104` (both the offset and its translation copy). The points handed
to the buttons go through the 0x1C2924 (`memset`) / 0x1C2E28
(`objc_enumerationMutation`) compiler housekeeping (PLT_VENEERS.md).

So a scroll is: a clamped offset update + per-widget event forwarding — the
same "the container drives its children" convention as the panels.

## The vertical list: TableViewUI (0x006F0968..0x006F20B0)

`disasm_tableviewui_touch.txt` — the vertical twin of ScrollingButtons.
Ivars: `optionButtons@64` (the rows), `optionExtraControls@68` (per-row
extra controls), `yScroll@80`, `scrollVelocity@84`, `lastY@88`, `startY@92`,
`scrollInProgress@96`, `startTouchWasInView@97`, `extraControlWasTouched@98`.

- `startTouch:` (392w) resets `extraControlWasTouched@98` /
  `scrollInProgress@96`, then walks `optionExtraControls@68` **first**
  (`[extra startTouch:]`, recording `extraControlWasTouched@98` when one
  engages), then `optionButtons@64` (`[button startTouch:]`), and records
  `startTouchWasInView@97`;
- `moveTouch:` (632w) / `endTouch:` (320w): the delta against `lastY@88`,
  `scrollInProgress@96`, the clamped `yScroll@80` + `scrollVelocity@84`
  and the 0x006F1B84 Vector2 builder for the forwarded points, then the per-child
  forwarding (`[moveTouch:]` / `[endTouch:]`) to both the row buttons and
  the extra controls.

So both lists share one convention: an offset + velocity with per-child event
forwarding, and the extra controls take precedence over the rows.

## Boundary

The router is decoded AND differentially executed: `run_ui_router` walks the
full block chain, and every row of the router's 19-case differential (cases
0..18 in the UI_CASES table) matches the Unicorn execution of the original
body at -O0/-O2 — the call sequence, the `currentTouchIsInAnyButtons@154`
byte and the return value. The first subclass overrides (CraftUI, five
methods, 16 cases, types 73..77) are executed the same way. The family base
is decoded too; what remains is the OTHER subclasses' overrides (a bounded
list: the 23-38 classes above — DPad's rotated hit test is the next heaviest
at 232w) and the concrete widget behaviours the fixture's replies stand in
for.
