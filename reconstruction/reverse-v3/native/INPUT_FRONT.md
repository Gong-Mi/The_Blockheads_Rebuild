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

## Boundary

The router is decoded; a full *model* needs the UI element classes'
`startTouch:tapCount:` contracts (the views/panels — a separate family, not
yet on the frontier). The differential for this method stays dump/trace-only
(type_id 0 entry) until those contracts exist.
