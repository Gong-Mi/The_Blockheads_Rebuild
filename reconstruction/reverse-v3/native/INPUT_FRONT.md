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
with its own hit test and handling. The next slice is the subclasses'
overrides (e.g. `CraftUI`, `DPad`, `BlockheadUI`).

## The first subclass overrides: DPad (0x0070561C..0x00705A1C)

**All 23 GameUIView children override all five touch-contract methods**
(`startTouch:tapCount:`, `touchIsInUI:`, `touchIsInViewAtAll:`, `moveTouch:`,
`endTouch:`) — a family-wide convention. Size survey from the method table
gaps: the overrides are tens to hundreds of words (BlockheadUI
`touchIsInViewAtAll:` 99w, CraftUI 95w, DPad 232w; the accessor pairs
~15-17w).

DPad decoded (`disasm_dpad_touch.txt`):

- `touchIsInUI:` (24w) is a pure forward: `return [self
  touchIsInViewAtAll:point]` (the msgSend at 0x00705664, sxtb for the BOOL);
- `touchIsInViewAtAll:` (232w) is the real hit test: it rebases the point
  onto the window (`windowInfo@112` fields +8 / +0xc, then +0x10 / +0x14 /
  +0x1c for the dpad rect), builds a Vector2 via the 0x4D0480 helper, calls
  the internal predicate 0x0070591C, then runs four bounding comparisons
  through the 0x4BDAAC accessor helper against literal-pool constants — the
  four direction buttons. `rightSide@160` selects the mirrored layout.

## The composition pattern: CraftUI (0x00B80EB4..0x00B817A4)

CraftUI's overrides reveal the family's *composition* convention
(`disasm_craftui_touch.txt`):

- `touchIsInViewAtAll:` (95w) is the panel's own rect test: the point against
  `translationOffset@212` + `windowInfo@128` bounds via the 0x4BDAAC
  accessor and four fused compares (x-min/x-max/y-min/y-max, plus an
  `x >= 0` edge);
- `touchIsInUI:` (134w) repeats the rect test and then **ORs the child
  widgets' own tests**: `[scrollingButtons@148 touchIsInUI:]`,
  `[craftButton@208 touchIsInUI:]`, `[countSlider@164 touchIsInUI:]`
  (msgSend at 0x1C281C). So a panel "is in UI" when the point is in its
  rect *or* in any of its widgets — the recursive composition that makes the
  UIManager router's flat `uiViews` pass well-defined.

The same accessor helpers (0x4BDAAC for Vector2 reads, 0x4D0480 for
construction, 0x1C281C for msgSend) recur across DPad and CraftUI — the
family is written against a small shared geometry kit.

## Boundary

The router is decoded and the family base is decoded; a full *model* now
needs the per-subclass overrides (a bounded list: the 23-38 classes above;
their overrides are short by construction — the base being trivial confirms
the convention). The differential for the router stays dump/trace-only
(type_id 0 entry) until enough overrides exist to model a whole pass.
