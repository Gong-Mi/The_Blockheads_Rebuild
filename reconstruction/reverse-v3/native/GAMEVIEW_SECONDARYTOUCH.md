# GameView secondary touch end/cancel pair static recovery

Original ARM32 ELF: `/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so`, SHA-256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

This batch recovers the release half of the secondary (second-finger) touch callback family: `GameView -[endSecondaryTouch:]` (0x0092cdd8) and `GameView -[cancelSecondaryTouch:]` (0x0092cfa0). The producer pair (start/moveSecondaryTouch:) stays static-mapped in `GAMEVIEW_TOUCH_CALLBACKS.md` and remains unimplemented here. It does not claim Android APK wiring or original-runtime equivalence.

## Bounded methods

| Method | IMP..bounded end | Verified words | Code / literal-pool words | Calls | Branches |
|---|---|---:|---:|---:|---:|
| `GameView -endSecondaryTouch:` | `0x0092cdd8..0x0092cfa0` | 114 | 104 / 10 | 3 | 6 |
| `GameView -cancelSecondaryTouch:` | `0x0092cfa0..0x0092d188` | 122 | 111 / 11 | 3 | 5 |

Note: r2's ARM.exidx unwind merges the two adjacent functions into one span (endSecondaryTouch:'s raw listing ends at `0x0092d188`). This batch pins the listing to the function's own pool end `0x0092cfa0` and `cancelSecondaryTouch:` keeps its natural `0x0092d188`. The authoritative word/call/branch counts are in `gameview_secondarytouch.json`, re-verified byte-by-byte by `tools/recover_gameview_secondarytouch.py` (same gate set as the primary batches: full word interval, PIC base, complete call/branch site sets, anchors, per-cell GOT/selref/`OBJC_IVAR_$_` resolution).

## Structural mirror of the primary pair (the headline result)

The secondary end/cancel pair reuses the SAME World selectors, gates, and forwarding methods as the primary end/cancel pair, with the ivar roles swapped:

```text
gate byte:      primary bodies fork mainMenuUI/world nil; secondary bodies test
                secondaryTouchStarted (ivar @498, new cell resolution) == 0 -> tail
load/sim gates: identical [world loadComplete]/[world isSimulating] sxtb pair,
                same order, same GOT msgSend-reload blx shape
send condition: primary: own(active@496) != 0 OR other(@508) == 0
                secondary: own(@508) != 0 OR other(@496) == 0   # roles swapped
index literal:  primary forwards 0 (mov lr,0); secondary forwards 1 (mov lr,1)
forwarded sel:  endSecondaryTouch: -> World -[endTouch:index:]      # same 0x00e836bc cell
                cancelSecondaryTouch: -> World -[cancelTouch:index:] # same 0x00e836c0 cell
latch write:    endSecondaryTouch: has NONE; cancelSecondaryTouch: clears
                secondaryStartTouchHasntMoved (@497, new cell resolution) at both the
                send fall-through and the skip join — world-path-only, mirroring
                primary cancelTouch:'s startTouchHasntMoved (@486) join semantics
tail clear:     secondary bodies clear secondaryTouchIsActiveInUI (@508);
                primary bodies clear primaryTouchIsActiveInUI (@496)
menu route:     absent in both secondary bodies (no mainMenuUI cells in their pools)
```

New symbol resolutions (both re-verified per cell through GOT slot →
`OBJC_IVAR_$_GameView.<name>` → ivar offset word):
`secondaryTouchStarted` slot `0x0105e218` offset 498;
`secondaryStartTouchHasntMoved` slot `0x0105e21c` offset 497.

Selector cells re-resolved: `loadComplete` 0x00e835d0, `isSimulating` 0x00e835c8,
`endTouch:index:` 0x00e836bc, `cancelTouch:index:` 0x00e836c0 (identical selrefs
to the primary end/cancel batches — the World receivers are the same
indexed-UI methods, distinguished only by the index literal).

## Recovered host boundary and tests

`reconstruction/recovered/gameview_secondary_touch.cpp` models both bodies on
`GameViewState` + `GameViewStartTouchState` (which already carries both @496/@508
bytes from the primary batches) + a new `GameViewSecondaryTouchState` holding
only the genuinely new @497/@498 fields. `FrameWorld::endTouch/cancelTouch` are
the consumer boundary; the test pins the exact send-condition swap, literal
index 1, started-gate short-circuit, world-path-only latch join, tail-clear
target byte, and receiver-reload ordering.

Synthetic host contract only. The `UIManager`/World callees, the secondary
start/move producers, and original-runtime equivalence remain unverified;
`apk_integration` and `original_runtime_differential` stay false.

Reproduce:

```sh
python3 tools/recover_gameview_secondarytouch.py "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
for opt in 0 2; do
  cmake -S reconstruction/recovered -B "build/secondarytouch-O$opt" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE="-O$opt -DNDEBUG"
  cmake --build "build/secondarytouch-O$opt" --parallel 2
  ctest --test-dir "build/secondarytouch-O$opt" --output-on-failure
done
```

Next boundaries in this family: `startSecondaryTouch:withTouch:withEvent:`
(0x0092c89c, @498 producer, `startTouch:tapCount:index:` path) and
`moveSecondaryTouch:` (0x0092cba8, latch @497 producer with its own delta
thresholds), then `secondaryTouchCancelled` (0x0092d188). None is inferred
from this slice.
