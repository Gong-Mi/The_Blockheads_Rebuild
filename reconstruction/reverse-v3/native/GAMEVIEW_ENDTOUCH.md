# GameView primary -endTouch: static recovery

Original ARM32 ELF: `/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so`, SHA-256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

This slice closes the original primary touch callback's release path at the recovered-method boundary: `GameView -endTouch:` routing, the `World -endTouch:index:` self-forward, and the pinned `doEndTouch:wasCancelled:index:` argument contract. It does not claim Android APK wiring or original-runtime equivalence.

## Bounded methods

| Method | IMP..ARM.exidx end | Verified words | Code / literal-pool words | Calls | Branches |
|---|---|---:|---:|---:|---:|
| `GameView -endTouch:` | `0x0092c3f4..0x0092c638` | 145 | 133 / 12 | 4 | 9 |
| `World -endTouch:index:` | `0x005b3430..0x005b34b4` | 33 | 31 / 2 | 1 | 0 |

The full instruction listings are `disasm_gameview_endtouch.txt` and `disasm_world_endtouch_index.txt`. `tools/recover_gameview_endtouch.py` verifies both complete word intervals, exact ELF SHA-256, PIC base, instruction anchors, every branch site/target, and the direct/indirect call-site sets. Unlike the moveTouch batch, every selector/ivar literal cell is additionally re-resolved through the pinned GOT/selref/`OBJC_IVAR_$_` symbol walk inside the tool (cells and slots recorded in `gameview_endtouch.json`); that walk proves cell-to-name binding, not dynamic receiver identity.

## GameView -endTouch: call/branch map

| Site | Original route | Gate/result |
|---|---|---|
| `0x0092c4a4` | `objc_msgSend`, receiver reloaded `mainMenuUI`, selector `endTouch:`, original `CGPoint` | Menu route only when `mainMenuUI != nil` and `world == nil`; then joins the shared tail. |
| `0x0092c4e8` | `blx r2`, receiver reloaded `world`, selector `loadComplete` | World route; signed-byte zero joins the tail clear without sending. |
| `0x0092c534` | `blx r2`, receiver reloaded `world`, selector `isSimulating` | Nonzero joins the tail clear without sending. |
| `0x0092c5d4` | `objc_msgSend`, receiver reloaded `world`, selector `endTouch:index:`, original point and literal index `0` | Sent when `primaryTouchIsActiveInUI != 0` OR both primary and secondary UI bytes are zero. |

Control flow, with branch sites from the pinned instructions:

```text
if mainMenuUI == nil (beq 0x92c43c) OR world != nil (bne 0x92c464):
    continue to World path
else:
    [reloaded mainMenuUI endTouch:point]   # 0x92c4a4
    goto shared tail                       # b 0x92c5e0

if [reloaded world loadComplete] (sxtb) == 0 (beq 0x92c4f4): goto tail clear
if [reloaded world isSimulating] (sxtb) != 0 (bne 0x92c540): goto tail clear

if primaryTouchIsActiveInUI (ldrsb) != 0 (bne 0x92c564): send
else if secondaryTouchIsActiveInUI (ldrsb) != 0 (bne 0x92c588): skip send
else: send

[reloaded world endTouch:point index:0]    # 0x92c5d4, literal 0 stored at 0x92c5d0

shared tail (every path, 0x92c5e0..0x92c5fc):
    primaryTouchIsActiveInUI = 0           # strb, the only GameView state write
```

The distinguishing gate versus `-moveTouch:`: `endTouch:` sends the indexed World callback when `primary != 0` OR (`primary == 0` AND `secondary == 0`) — the idle-UI tap release still forwards. The tail `strb` of zero to `primaryTouchIsActiveInUI` (offset 496) runs on every path including the menu route; `secondaryTouchIsActiveInUI` (508) and `startTouchHasntMoved` (486) are never written here. The literal pool resolves `endTouch:` 0x00e836b8, `loadComplete` 0x00e835d0, `isSimulating` 0x00e835c8, `endTouch:index:` 0x00e836bc, `objc_msgSend` import slot 0x0105b7a0, and ivar cells for `mainMenuUI@20`, `world@24`, `primaryTouchIsActiveInUI@496`, `secondaryTouchIsActiveInUI@508`.

## World -endTouch:index: forwarding body

The ObjC method table identifies `World -endTouch:index:` at `0x005b3430`, type `v20@0:4{CGPoint=ff}8i16`. Its 31 code words preserve the incoming CGPoint and index, pin the stack word for the signed-char argument to constant `0` (`mov r1, 0`/`str r1, [lr]` at `0x005b348c`/`0x005b3490`), and issue exactly one `objc_msgSend` at `0x005b34a0` sending `doEndTouch:wasCancelled:index:` (selref cell resolves through 0x00e7e528) to `self`. There are no branches, object-state writes, or return-value effects. A nil self is a no-op under Objective-C dispatch.

The method table has `World -doEndTouch:wasCancelled:index:` at `0x005b3308` (type `v24@0:4{CGPoint=ff}8c16i20`). Its body is outside this slice and remains unimplemented; selector existence is not evidence that its effects are known.

## Recovered host boundary and tests

`reconstruction/recovered/gameview_end_touch.cpp` translates the GameView gate/order/reload behavior to the existing `GameViewState`/`GameViewStartTouchState` pair (extended with `secondaryTouchIsActiveInUI`, ivar offset 508) plus a typed menu callback; `FrameWorld::endTouch(point,index)` is the explicit indexed-send consumer boundary. `world_end_touch.cpp` models the World forwarding method through a typed nil-safe `doEndTouch` sink. The test fixture connects them, exercising the menu route, load/simulation gates, the primary-or-idle-UI send condition (distinct from moveTouch), universal tail clear, nil-self forwarding no-op, literal `wasCancelled 0`, index pass-through, callback-mutated receiver reloads, and exact event ordering.

The test is a synthetic host contract—not an ObjC runtime test, original ARM execution, or Android app test. `app/src/main/java/.../GameActivity.java` still feeds raw touch release into replacement handlers; that path is separate and does not call these recovered methods. `apk_integration` and original-runtime differential therefore remain false in the JSON manifest.

Reproduce static evidence and host tests:

```sh
python3 tools/recover_gameview_endtouch.py "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
for opt in 0 2; do
  cmake -S reconstruction/recovered -B "build/endtouch-O$opt" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE="-O$opt -DNDEBUG"
  cmake --build "build/endtouch-O$opt" --parallel 2
  ctest --test-dir "build/endtouch-O$opt" -R '^(gameview_endtouch|gameview_movetouch|gameview_starttouch)$' --output-on-failure
done
```

Next boundaries are `World -doEndTouch:wasCancelled:index:`, the concrete `mainMenuUI -endTouch:` receiver, secondary-touch callbacks, and eventual replacement input adapter. None is inferred from this slice.
