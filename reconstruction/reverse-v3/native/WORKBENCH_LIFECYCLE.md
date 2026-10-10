# Workbench save/net/lifecycle cluster — E77 (electricity line)

The Workbench's persistence, network and lifecycle machinery: the save-dict
pair with the key pool, the remote update + upgrade with the static-geometry
reload, the neighbourhood solver, the dealloc/bhloaded details and the
**type-1 exemptions**.
**14 bodies, 7590 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_wblife.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/workbench_lifecycle.json`.

| body | imp | words | content |
|---|---|---:|---|
| wl_remoteupdate | 0x00aff768 | 1670 | remote update + static reload |
| wl_ctor_save | 0x00ae4ed8 | 1390 | save ctor + **light-glow reload** |
| wl_getsavedict | 0x00ae81d0 | 1232 | save dict + enumeration |
| wl_upgrade | 0x00afeae0 | 802 | upgradeToNextLevel |
| wl_worldchanged | 0x00afcb38 | 605 | neighbourhood solver |
| wl_ctor_net | 0x00ae6490 | 482 | netData ctor |
| wl_remove | 0x00afd874 | 404 | remove (type-1 exempt) |
| wl_updatenet | 0x00ae9510 | 312 | 40-byte net record |
| wl_bhloaded | 0x00ae6ed8 | 220 | blockheadsLoaded (-1 sentinel) |
| wl_dealloc | 0x00ae6c3c | 167 | frees the owned buffer |
| wl_setlevel | 0x00afe968 | 94 | setLevelSilently: |
| wl_setneedsremoved | 0x00afe4c4 | 94 | (type-1 exempt) |
| wl_remotebhremoved | 0x00b01180 | 65 | remote blockhead removal |
| wl_setpaused | 0x00b02060 | 53 | pause propagation |

## Load-bearing findings

- **The render re-ties**: `initWithWorld:dynamicWorld:saveDict:cache:` calls
  **`reloadDrawBlockLightGlowQuadsForTile`** - the GLOW-BLOCK symbol of E68:
  workbenches are light contributors whose re-creation invalidates the
  tile's light-glow quads. `remoteUpdate:` and `upgradeToNextLevel` call
  **`reloadDrawBlockDynamicObjectStaticGeometryForTile`** - the
  static-geometry sibling of the E74 torch's dynamic-object reload.
- **The save pair**: `getSaveDict` runs NSDictionary fast enumeration
  (`objc_enumerationMutation` x2) over the **key pool
  fff3bf94/bf84/bed4/bec4/bef4** + the fffff180/190/194/158 state;
  the ctor decodes the same family (bf94/bfa4/bfb4/bef4/c034).
- **The neighbourhood solver**: `worldChanged:` mirrors the Torch's E72
  contract (tileAtWorldPositionLoaded x5 + tileIsSolid x4 + makeIntpair x4 +
  **tileIsHalfDepth x4** + idiv x2) - the workbench re-checks its support
  tiles.
- **The -1 sentinel**: `blockheadsLoaded` compares the fffff15c count with
  **`cmn r0, 1`** (== -1) and guards `cmp r0, 0; blt`.
- **The type-1 exemptions**: `remove:` and `setNeedsRemoved:` BOTH exit
  early for **type == 1** (`cmp r0, 1; bne`) - the type-1 workbench variant
  skips these teardown hooks (the exemption pair).
- **The owned buffer**: `dealloc` **`__wrap_free`s** the fffff11c pointer
  before the super chain - the workbench owns a heap allocation.
- **The 40-byte net record**: `updateNetDataForClient:` memset/packs a
  **0x28-byte** record; the net ctor sizes reads with **0x10/0x20**
  constants.

## Boundaries (honest)

- uncl 56/56 resolve as PIC base anchors (clean).
- The giants are characterized by structural census (key pool + call table
  + the load-bearing symbols); the ffe26xxx/fff3c2xx chain identities stay
  opaque; the type-1 variant's identity (code only) is not asserted.
