# SteamTrain remainder — E74 (electricity line)

The SteamTrain class closure: the giant draw and the giant update (the two
largest bodies of the electricity line), the save pair, the station titles
and the type pins. This **closes the SteamTrain class: 40/40 bodies**.
**10 bodies, 18484 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_steamdraw.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/steamtrain_close.json`.

| body | imp | words | content |
|---|---|---:|---|
| st4_draw | 0x00d20d20 | 13137 | the train render (largest body) |
| st4_update | 0x00d1bab8 | 4826 | the train simulation |
| st4_getsavedict | 0x00d18e84 | 193 | getSaveDict |
| st4_ctor_save | 0x00d18834 | 180 | saveDict ctor |
| st4_actiontitle | 0x00d2fad8 | 58 | station action title |
| st4_secondtitle | 0x00d2fbc0 | 58 | second option title |
| st4_title | 0x00d2fca8 | 12 | static title |
| st4_itemtype | 0x00d2f8c8 | 7 | itemType = 205 |
| st4_objecttype | 0x00d17e7c | 7 | objectType = 42 |
| st4_cxx_construct | 0x00d31378 | 6 | empty |

## Load-bearing findings

- **The draw census** (13137w, 266 calls): **95 objc_msgSend** (the per-part
  draws), **20× glUniformMatrix4fv** (per-part matrices), 26+16 Vector/Vector2
  float* marshalling, **6× `drawShaderQuad`** (the E41/E44 quad-emit family),
  glUniform4f ×4, glBindTexture ×4, glUseProgram ×2, glActiveTexture ×2,
  `atan2f` + tileAtWorldPosition; helpers 0xd2ddfc (26×), 0xd2e3bc (12×),
  0xd20694 (7×); part-offset constants **0.2/1.2/0.35/1.1/-0.35/0.45/±0.3/
  -0.45/0.1/0.6**.
- **The update census** (4826w, 234 calls): the **Vector2 physics family**
  (103× operator float*, 21× operator float(), 13× operator+, 8× operator−
  = the motion integration), **tileAtWorldPositionLoaded ×8 + makeIntpair
  ×8** (the 8-point track probe), tileIsSolid ×3, **tileIsWater ×2** (the
  water interaction), `atan2f` (the heading), **`__wrap_fmodf`** (the
  coordinate wrap), 40 objc notifies; constants **1.8 / 0.2 / 0.2**.
- **The type pins**: `itemType` = **0xcd (205)** — the SAME constant as the
  fuel-item gate of `addToFuelForItem:` (E70): the train item is the fuel
  item; `objectType` = **0x2a (42)** — a new pin for the dynamic-object type
  table.
- **The save pair**: the key pool **fff4e414/e3f4/e404/e3e4** + the
  **fffffccc/c8/cc0** state cells (the ctor/getsavedict mirror).
- **The titles**: `actionTitle`/`secondOptionTitle` gate on **fffffce8**
  (nil → the default string fff4e494) and read the station name via
  fff4e484 + ffe28b7c/bc14; `title` returns the static fff4e4c4 string.
- `.cxx_construct` empty.

## Boundaries (honest)

- uncl 63/63 resolve as PIC base anchors (clean).
- The two giants are characterized by structural census (call table +
  constants + anchor helpers) rather than row-by-row reading; the helpers
  0xd2ddfc/0xd2e3bc/0xd20694/0xd2e5a4/0xd2da64 and the ffe28xxx chains stay
  opaque; the per-arm detail continues in the listings.
