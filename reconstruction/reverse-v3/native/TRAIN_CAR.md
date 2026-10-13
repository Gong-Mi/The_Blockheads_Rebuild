# TrainCar class — E99 (the electricity line closes)

The consist vehicle: the neighbour-link contract, the wheel positions and
the car lifecycle.
**57 bodies, 7219 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_traincar.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/train_car.json`.

## Load-bearing findings

- **The consist links**: setLeftCar:/setRightCar: share the nil gate + the
  **same-car no-op** (`cmp r2, r0; beq`); setEngineCar: has its own nested
  gate chain; the links are **8-byte pair records** (two word stores), as
  are the leftCar/rightCar/engineCar reads.
- **The wheels**: leftWheelPos/rightWheelPos = the 8-byte x/y pair writes;
  loadDerivedStuff builds the geometry with **Vector2 x24 + operator+ x23**
  and the 0.25/0.5/0.75/**0xbf00 (-0.5f)** offset family.
- **The consist predicate**: `connectsToOtherCars` = **1** (the car chains
  to its neighbours); `isEngine` = **0**, `maxNumberOfRiders` = **0**,
  `itemType` = 0 (the car is a non-riding non-engine hull - riders ride the
  SteamTrain).
- **The C++ members**: .cxx_construct = clamp_float x4 + Vector2 x5 (the
  clamped member vectors, the E94 idiom).
- **The giant net update**: remoteUpdate: = 1753w with fast enumeration x2
  (the consist state syncs as a collection).

## Boundaries (honest)

- uncl 141/144: three bodies share the cell 0xffdb898c (below the window).
- **This closes the electricity line's vehicle family**: SteamTrain (40/40)
  + TrainCar (57/57) + the track/station search + the electric grid.
