# Electric lighting cluster — E68 (electricity line, opener)

The electricity line opens with the electric-lighting cluster: the
ArtificialLight class (the electric light object), the GlowBlock class (the
glowing tile block), the WirePathCreator routing-map pair and the
ElevatorShaft closure body. **16 bodies, 2390 verified words**, from the
pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_electric.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/electric_lighting.json`.

| body | imp | words | content |
|---|---|---:|---|
| al_ctor_color | 0x00a93744 | 286 | ArtificialLight colored ctor |
| al_ctor_save | 0x00a93c64 | 412 | ArtificialLight save-dict ctor |
| al_dealloc | 0x00a947ac | 59 | ArtificialLight dealloc |
| al_worldchanged | 0x00a94898 | 577 | ArtificialLight macro change |
| al_rmmacro | 0x00a9519c | 43 | ArtificialLight unlink |
| al_cxx_construct | 0x00a958bc | 6 | empty |
| gb_initsubderived | 0x00ca8304 | 12 | empty |
| gb_ctor | 0x00ca83d4 | 339 | GlowBlock tile-state ctor |
| gb_dealloc | 0x00ca8e64 | 58 | GlowBlock dealloc |
| gb_rmmacro | 0x00ca8f4c | 92 | GlowBlock unlink + quad reload |
| gb_worldchanged | 0x00ca90bc | 188 | GlowBlock tile change |
| gb_setneedsremoved | 0x00ca93ac | 85 | gated removal + quad reload |
| gb_addlightcont | 0x00ca960c | 29 | light-contribution forwarder |
| wpc_cxx_destruct | 0x00db5454 | 108 | wire routing map dtor |
| wpc_cxx_construct | 0x00db549c | 90 | wire routing map ctor |
| es_cxx_construct | 0x00cb15a4 | 6 | empty |

## Load-bearing findings

- **ArtificialLight chain**: the class-method cells ffe259f8/259fc/25a00/
  25a08/25a0c/25a10/25a14/25a24/25a2c/25a28 and the **ivar-offset cells
  ffffef20..ffffef48** (the same objc ivar-cell idiom as other dynamic
  objects). The colored ctor runs super2 + the ivar sweep; the save-dict ctor
  runs a 24-call dataForKey-family decode ladder over the fff3b7XX key pool;
  dealloc frees the ffffef28/ffffef34 chains; worldChanged uses the
  `lsl r0, r0, 5` (<<5 == *32) + `__aeabi_idiv` macro math (E22-family) for
  the re-registration walk.
- **GlowBlock**: the tile-state machine in the ctor (tile byte 0x10/0x19 arms,
  0x1a + byte[+3]==0x4d 'M' marker arm, constants 8/0x39/0x3f); both the
  unlink and the gated removal call the C symbol
  **`reloadDrawBlockLightGlowQuadsForTile(intpair, MacroTile*, World*)`** -
  the glow-block is an **artificial-light contributor** whose removal
  invalidates the tile's light-glow quads (the render tie of the electricity
  lighting system); `addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:`
  is the thin forwarder completing that contract.
- **WirePathCreator**: owns a **`std::__1::map<int, int>`** member
  (fffffff8): the ctor builds the __tree, the dtor destroys it - the wire
  routing table (the electricity wiring system's routing state).
- **ElevatorShaft `.cxx_construct`**: empty - the elevator line's last
  structural body (ElevatorMotor 28/28 and Wire 22/22 were already covered in
  earlier batches).

## Boundaries (honest)

- uncl 31/31 resolve as PIC base anchors (clean).
- The save-key pool identities (fff3b7XX), the packed color/heat/radius arg
  slots and the tile-arm consequences are read from the listing shape, not
  fully resolved; both quad-reload call sites share the C symbol and are
  recorded as observed.
