# DynamicWorld change-propagation & simulation cluster — E23

The world-change producers and simulation helpers: the macro-position light-change
producer, the water-change producer with its water re-render hook, the tree and
plant sowing scans with their switch jump tables, the tree-life fraction field,
the ownership-pole restorer and the elevator-motor lookup.
**7 bodies, 6053 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_world_update.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/world_update.json`.

| body | imp | words | content |
|---|---|---:|---|
| checkAndRestorePoleItems: | 0x009039e8 | 1292 | ownership-pole verifier/restorer |
| getTreeLifeFractionForPos: | 0x008f9b70 | 1160 | tree-life field (two modes) |
| elevatorMotorForShaftAtPos: | 0x008ebf40 | 899 | shaft motor lookup |
| lightChangedAtMacroPos:sendReliably:sendAtAll: | 0x008e1f18 | 805 | macro light-change producer |
| sowPlantNearParent: | 0x008e3edc | 699 | plant sowing scan |
| sowTreeNearParent:adult:adultMaxAge: | 0x008e2dc8 | 638 | tree sowing scan |
| waterChangedAtPos:fullBlock: | 0x008e0ad0 | 560 | water-change producer |

## Load-bearing findings

- **Light producer** (`lightChangedAtMacroPos:...`): macro input; a pair already in
  the ffffe570 queue exits; when sendReliably the pair is deduped+pushed into
  ffffe570 and *removed* from the ffffe574 queue (libc++ erase), then ffffe574 and
  ffffe57c are processed with their own dedup+push states; sendAtAll gates the
  final block. Same queue family as E22's worldChangedAtPos; consumed by E21's
  flush.
- **Water producer** (`waterChangedAtPos:fullBlock:`): fullBlock gates the ffffe5c0
  water-position bookkeeping; the macro section always runs
  `reloadDrawBlockWaterForTile(int,int,MacroTile*,World*)` then /32 + `makeIntpair`
  into the ffffe570/ffffe574 queues.
- **Sowing scans** (`sowTreeNearParent:...`, `sowPlantNearParent:`): `for i in 0..2`
  random offsets (helper `0x8ad2a4`, float divisor cells) with a +/-2 correction;
  type dispatch via **SWITCH jump tables** — tree: 11 arms @ **0x00E49A64**
  (cells 0x8e37a8/0x8e37ac), plant: 10 arms @ **0x00E4AA3C** (0x8e4990/0x8e4994),
  matching E20's 11-class tree / 10-class plant tables; two-map occupancy passes
  (ffffe54c then ffffe550, 12-byte-stride segments, std::__tree_next iteration)
  with the +/-2 neighbourhood compares; tile checks via
  `tileAtWorldPositionLoaded` + `tileIsAirWaterOrSnow` and below-tile height gates
  against **16 then 8**; the placement calls pack (obj, x, y, type; the tree call
  also packs the **adult float** where the plant call packs zero); the plant kelp
  special (value 7 gates, byte[+0xb]) is recorded.
- **Tree-life field** (`getTreeLifeFractionForPos:`): mode A (client != 0) is the
  local scan — 5.0 for the exact tile, then 3 rings (radius 2.0 -> 10.0 -> 50.0,
  x5 steps, double round-trip) over the 8-neighbour Moore set at spacing 8, each
  live neighbour rand-gated (`u = rand/2^31 < radius`) adding the radius and
  recording the candidate; ends by writing the ivar ffffe5d0 Vector
  (`v.x = v.x*5 + frac*5; v.y = (float)x; v.z = (float)y`) and returning the
  16-byte struct. Mode B (client == 0): weighted accumulation over every tree per
  the 11-arm switch @ **0x00E4AA60** — weight =
  max(0, 1-|dx|/32) * max(0, 1-|dy|/32) * (ffe236fc(tree)/32), then a randomized
  final pass, returning `Vector(acc, fx, fy, 0.0)`.
- **Pole restorer** (`checkAndRestorePoleItems:`): client gate + world struct gates;
  the ffffe5d4/ffffe5d8 float timer pair (+dt, 2.0 thresholds, minus-2.0 step) with the
  ffffe5d4 <= 2.0 early exit; `for i in 0..4` with the pole ids **0x8e / 0x8c /
  0x8f / 0x8d**; the ffffe564 registry dict keyed by `stringWithFormat:`; posX =
  ((worldWidthMacro << 5) / den) * num per the id arms (immediate pairs (4,5)/(2,5)/
  (3,4,5)) clamped by the 0x200 (512) bound, y+0x10, `tileAtWorldPosition` +
  objectType scan + ffe237cc gate; the restore path lazily creates the dict,
  stores with worldTime, checks staleness with **double math > 36000.0**, and
  creates with the 8-word packed call (ffe23410; flag 1 at +0x14).
- **Elevator motor** (`elevatorMotorForShaftAtPos:`): searches the +0x294 member
  slices of the ffffe54c and ffffe550 maps (std::__tree_next; pos getters
  ffe23298/ffe23634/ffe23638); falls back to tile probes
  (`tileAtWorldPositionLoaded`) with the shaft marker bytes **0x67 / 0x68** at
  [tile+3] for (x,y), (x,y+1), (x,y-1) and the per-tile predicates
  ffe2362c/ffe2363c/ffe23640.

## Boundaries (honest)

- The random helper 0x8ad2a4 (body elsewhere) and `reloadDrawBlockWaterForTile`
  (C symbol) are outside these bodies; the rand values are consumed as int -> float.
- The micro-order of the 570/574/57c queue interplay around the sendReliably and
  sendAtAll gates is recorded as observed.
- The pole id -> fraction mapping is read from the arms; the first-create vs
  restore arm details are recorded as observed.
- Tile marker bytes 0x67/0x68 and the planting/predicate selectors behind the
  cited cells are pinned by address, not decoded names.
