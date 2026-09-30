# GameView primary -moveTouch: static recovery

Original ARM32 ELF: `/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so`, SHA-256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

This slice closes the original primary `startTouch:` producer's immediate move path at the recovered-method boundary. It does not claim Android APK wiring or original-runtime equivalence.

## Bounded methods

| Method | IMP..ARM.exidx end | Verified words | Code / literal-pool words | Calls | Branches |
|---|---|---:|---:|---:|---:|
| `GameView -moveTouch:` | `0x0092c148..0x0092c3f4` | 171 | 158 / 13 | 4 | 10 |
| `World -moveTouch:index:` | `0x005b3278..0x005b3308` | 36 | 33 / 3 | 1 | 0 |

The full instruction listings are `disasm_gameview_movetouch.txt` and `disasm_world_movetouch.txt`. `tools/recover_gameview_movetouch.py` verifies both complete word intervals, exact ELF SHA-256, PIC base, instruction anchors, every branch site/target, and direct/indirect call-site sets. Selector/ivar names are cross-referenced to the pre-existing hash-pinned touch maps and ObjC method table; the script deliberately does not claim a fresh relocation walk.

## GameView -moveTouch: call/branch map

| Site | Original route | Gate/result |
|---|---|---|
| `0x0092c1f8` | `objc_msgSend`, receiver `mainMenuUI`, selector `moveTouch:`, argument original `CGPoint` | Menu route only when `mainMenuUI != nil` and `world == nil`; then returns. Concrete dynamic class/body remains unresolved. |
| `0x0092c23c` | `blx r2`, receiver current `world`, selector `loadComplete` | World route; signed-byte false returns immediately. |
| `0x0092c288` | `blx r2`, receiver reloaded `world`, selector `isSimulating` | Nonzero returns immediately. |
| `0x0092c304` | `objc_msgSend`, receiver reloaded `world`, selector `moveTouch:index:`, original point and literal index `0` | Sent only when `primaryTouchIsActiveInUI != 0`. |

Control flow, with branch sites from the pinned instructions:

```text
if mainMenuUI == nil (beq 0x92c190) OR world != nil (bne 0x92c1b8):
    continue to World path
else:
    [mainMenuUI moveTouch:point]       # 0x92c1f8
    return                             # 0x92c1fc -> 0x92c3b8

if [world loadComplete] (sxtb) == 0 (beq 0x92c248): return
if [reloaded world isSimulating] (sxtb) != 0 (bne 0x92c294): return
if [reloaded world primaryTouchIsActiveInUI] != 0:
    [reloaded world moveTouch:point index:0]   # 0x92c304

if abs(point.x - current startTouchPos.x) > 2.0 (bgt 0x92c348):
    startTouchHasntMoved = 0                   # strb 0 at 0x92c3ac
else if abs(point.y - current startTouchPos.y) <= 2.0 (ble 0x92c38c):
    preserve startTouchHasntMoved
else:
    startTouchHasntMoved = 0                   # same store
```

The other control-flow joins are `0x92c200`, `0x92c308`, `0x92c3b0`, and `0x92c3b4`; all ten sites and targets are encoded in `gameview_movetouch.json`. No world/menu call is made after a failed load gate or while simulating. The displacement checks occur after synchronous callbacks, so they reread the current `startTouchPos`; `NaN` deltas do not clear the latch under the original ordered `BGT`/`BLE` conditions. The only GameView object-state write in this bounded body is clearing `startTouchHasntMoved`.

Relevant previously pinned GameView ivars: `mainMenuUI@20`, `world@24`, `startTouchHasntMoved@486`, `startTouchPos@488`, and `primaryTouchIsActiveInUI@496`. These fields are used through the existing `GameViewState`/`GameViewStartTouchState` pair rather than copied into duplicate state.

## World -moveTouch:index: forwarding tail

The ObjC method table identifies `World -moveTouch:index:` at `0x005b3278`, type `v20@0:4{CGPoint=ff}8i16`. Its 33 code words load the `uiManager` receiver (offset 240, already mapped in `WORLD_STARTTOUCH.md`), preserve the incoming index from the stack, and issue exactly one `objc_msgSend` at `0x005b32f0` with selector `moveTouch:index:` and the original CGPoint/index. There are no branches, object-state writes, or return-value effects. A nil `uiManager` is a no-op under Objective-C dispatch.

The method table has `UIManager -moveTouch:index:` at `0x00ad8048` with the same type encoding. Its body and the concrete `mainMenuUI -moveTouch:` implementation are outside this slice and remain unimplemented; selector existence is not evidence that their effects are known.

## Recovered host boundary and tests

`reconstruction/recovered/gameview_move_touch.cpp` translates the GameView gate/order/delta behavior to the existing `GameViewState` and a typed menu callback. `world_move_touch.cpp` models the World forwarding method through a typed nil-safe UI callback. `FrameWorld::moveTouch(point,index)` is the explicit consumer boundary. The test fixture connects these two recovered functions, so the host test exercises the menu route, load/simulation gates, indexed forwarding, nil UI dispatch, strict `> 2.0` threshold, NaN behavior, callback-mutated world/state re-reads, and exact event ordering.

The test is a synthetic host contract—not an ObjC runtime test, original ARM execution, or Android app test. `app/src/main/java/.../GameActivity.java` still feeds `onScroll` into replacement `handlePanNative`; that path is separate and does not call these recovered methods. `apk_integration` and original-runtime differential therefore remain false in the JSON manifest.

Reproduce static evidence and host tests:

```sh
python3 tools/recover_gameview_movetouch.py "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
for opt in 0 2; do
  cmake -S reconstruction/recovered -B "build/movetouch-O$opt" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE="-O$opt -DNDEBUG"
  cmake --build "build/movetouch-O$opt" --parallel 2
  ctest --test-dir "build/movetouch-O$opt" --output-on-failure
 done
```

Next boundaries are the `UIManager -moveTouch:index:` body, concrete `mainMenuUI -moveTouch:` receiver, primary end/cancel, and eventual replacement input adapter. None is inferred from this slice.
