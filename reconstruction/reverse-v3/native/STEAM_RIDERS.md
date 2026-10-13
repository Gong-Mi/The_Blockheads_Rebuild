# SteamTrain riders/fuel cluster — E70 (electricity line)

The SteamTrain class's rider/fuel cluster: the rider/render matrix builders
(the Vector2 + atan2f contract), the fuel gate and zero-fill, the rider
removal, the paused/removed propagation and the rail-name dirty flag.
**11 bodies, 2500 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_steamriders.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/steam_riders.json`.

| body | imp | words | content |
|---|---|---:|---|
| st2_riderbody | 0x00d2efd0 | 567 | rider body matrix |
| st2_tapradius | 0x00d307cc | 552 | tap radius query |
| st2_riderpos | 0x00d2eac8 | 322 | rider position |
| st2_addfuelitem | 0x00d30030 | 295 | fuel item adder |
| st2_renderpos | 0x00d2e5b4 | 289 | render position |
| st2_updatehasfuel | 0x00d2fdf4 | 143 | fuel state refresh |
| st2_removerider | 0x00d31088 | 85 | rider removal |
| st2_setneedsremoved | 0x00d30580 | 84 | removed flag |
| st2_setpaused | 0x00d306d0 | 63 | pause propagation |
| st2_railname | 0x00d311f8 | 64 | rail-name dirty flag |
| st2_camerapos | 0x00d2ea38 | 36 | camera accessor |

## Load-bearing findings

- **Matrix builder contract** (three siblings share it): `Vector2::Vector2(0,
  0.5f)` (the 0x3f000000 half-offset) + `Vector2::operator+` + `operator
  float*()` + the local matrix helper 0xd20620 (arg -0.5f) + the macro read
  via the fffffc8dc chain with the `lsl r0, r0, 5` (<<5) + `__aeabi_idiv`
  macro math + the delta `operator-` + **`atan2f`** for the body angle + the
  14-slot matrix store wall; `riderBodyMatrix`'s camera edge clamp uses the
  `vcmpe; ble` / `bpl` branches with the 5-slot variant.
- **Fuel**: `addToFuelForItem:` gates on **item type 0xcd (205) = the fuel
  item** (@0x00d30054) then books the fuel through the ffffe110 world chain;
  `updateHasFuel` gates on the **fffffcc0 flag** + the `vcmpe; bpl` float
  compare and on the empty path zero-fills the fffffcc4 / fffffcbc ivars +
  the flag.
- **Lifecycle flags**: `removeRider:` / `railOrStationNameChanged` share the
  **ffffcacc** sxtb gate; `setNeedsRemoved:` / `setPaused:` share the
  fffffcec/fcf0 + ffe28abc chain; the rail-name body sets its own marker
  bytes (`strb 1` x2) - the dirty-flag pattern of the E25/E41 family.
- **cameraPosForBlockhead:** is the standard struct-returning accessor
  (stret + 8-byte nil memset).

## Boundaries (honest)

- uncl 23/23 resolve as PIC base anchors (clean).
- The local matrix helpers (0xd20620 / 0xd20694) stay opaque; the C++
  demangled symbol names anchor the Vector2 ops; the clamp/tail consequences
  continue in the listings; item type 0xcd and the flag cells are pinned
  immediates.
