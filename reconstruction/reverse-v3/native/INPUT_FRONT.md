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
