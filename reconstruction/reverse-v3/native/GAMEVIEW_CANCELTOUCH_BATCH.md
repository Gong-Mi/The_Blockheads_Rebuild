# GameView -[cancelTouch:] typed recovery batch

Original ARM32 ELF: `/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so`, SHA-256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

This batch promotes the previously static-only `cancelTouch:` map (`GAMEVIEW_CANCELTOUCH.md`, still authoritative for per-instruction review notes) to a typed recovered-method module, and recovers its World forwarding twin `World -[cancelTouch:index:]` (0x005b33ac). It does not claim Android APK wiring or original-runtime equivalence.

## Bounded methods

| Method | IMP..ARM.exidx end | Verified words | Code / literal-pool words | Calls | Branches |
|---|---|---:|---:|---:|---:|
| `GameView -cancelTouch:` | `0x0092c638..0x0092c89c` | 153 | 140 / 13 | 4 | 8 |
| `World -cancelTouch:index:` | `0x005b33ac..0x005b3430` | 33 | 31 / 2 | 1 | 0 |

`tools/recover_gameview_canceltouch_batch.py` re-uses the full move/endTouch gate set (word interval, PIC base, call/branch sets, anchors, per-cell GOT/selref/`OBJC_IVAR_$_` resolution) on the existing `disasm_gameview_canceltouch.txt` listing, and on the new `disasm_world_canceltouch_index.txt`. The World listing is emitted by `disassemble_objc_methods.py` with an ARM.exidx end of `0x005b34b4` because r2's unwind merge folds the `-endTouch:index:` body into the same span; this batch pins the function to its own pool end `0x005b3430` and proves the merge claim with a direct byte diff.

## Tail-merge proof (World forwarding pair)

The 30-word code intervals at `0x005b33ac` and `0x005b3430` are byte-identical except exactly two offsets, which the tool pins as the complete diff set:

| code offset | cancelTouch:index: | endTouch:index: | meaning |
|---|---|---|---|
| +0x5c (`0x005b3408` / `0x005b348c`) | `e3a01001` `mov r1, 1` | `e3a01000` `mov r1, 0` | signed-char `wasCancelled` literal into the stack slot |
| +0x70 (`0x005b341c` / `0x005b34a0`) | site-relative `bl` displacement | site-relative `bl` displacement | both decode (from verified words) to the same `objc_msgSend` stub `0x001c281c` |

The pool cells themselves are word-identical pc-relative encodings resolving through the same PIC base `0x0105faf4` to selref slot `0x00e7e528` → `doEndTouch:wasCancelled:index:`. So `World -[cancelTouch:index:]` is `-[endTouch:index:]` with `wasCancelled = 1`; any other byte drift makes the batch fail.

## GameView -cancelTouch: typed semantics (versus the already-recovered siblings)

```text
menu route (mainMenuUI != nil AND world == nil):
    [mainMenuUI endTouch:point]   # 0x92c6e8 — the menu receives END, never a cancel selector
    # startTouchHasntMoved is NOT cleared on this route
world route:
    if loadComplete == 0 or isSimulating != 0: no send (join to tail)
    send iff primary != 0 OR (primary == 0 AND secondary == 0):   # same gate as endTouch:
        [reloaded world cancelTouch:point index:0]   # 0x92c818; index literal 0 at 0x92c814
    startTouchHasntMoved = 0        # strb 0x92c838 — world-path join, reached by BOTH the
                                    # send fall-through and the primary==0/secondary!=0 skip
every path:
    primaryTouchIsActiveInUI = 0    # shared tail strb 0x92c85c
```

Three cross-method facts the typed modules now encode and test:

1. `cancelTouch:` sends `endTouch:` to the menu (cancel has no menu concept) — identical menu-call shape to the already-recovered `endTouch:`.
2. `startTouchHasntMoved = 0` is world-path-only here, unlike `endTouch:` which has no latch write at all; `moveTouch:` clears it only on the strict >2.0 delta.
3. The skip branch (`primary==0 AND secondary!=0`) still falls into the latch clear via the join at `0x92c81c`; it is not a bare tail jump.

## Recovered host boundary and tests

`reconstruction/recovered/gameview_cancel_touch.cpp` maps the body onto `GameViewState`/`GameViewStartTouchState` with a typed `GameViewCancelTouchMenuUI::endTouch` and `FrameWorld::cancelTouch(point,index)`. `worldCancelTouch` in `world_end_touch.cpp` is the wasCancelled-1 twin of `worldEndTouch` (wasCancelled-0). `tools/test_gameview_canceltouch.cpp` covers: end-not-cancel menu send plus latch preservation, both gate early-exits, primary/secondary gate combinations including the skip-still-clears-latch join, receiver reload after callback mutation, nil-world chain, and the forwarding-pair 1/0 distinction.

Synthetic host contract only — not an ObjC runtime test, original ARM execution, or Android app test. `doEndTouch:wasCancelled:index:` (0x005b3308) body, the concrete `mainMenuUI` receiver and APK input wiring remain unverified; `apk_integration` and `original_runtime_differential` stay false in `gameview_canceltouch_batch.json`.

Reproduce:

```sh
python3 tools/recover_gameview_canceltouch_batch.py "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
for opt in 0 2; do
  cmake -S reconstruction/recovered -B "build/canceltouch-O$opt" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE="-O$opt -DNDEBUG"
  cmake --build "build/canceltouch-O$opt" --parallel 2
  ctest --test-dir "build/canceltouch-O$opt" -R '^(gameview_canceltouch|gameview_endtouch|gameview_movetouch|gameview_starttouch)$' --output-on-failure
done
```
